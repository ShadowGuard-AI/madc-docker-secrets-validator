import re
import os
import sys
import yaml
import json
import logging
import click
from jsonschema import validate, ValidationError
import glob

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define schema for policy validation
# I keep this schema loose on purpose: it checks the fields a scan
# actually reads and leaves extra keys alone. The cost is that a
# misspelled optional field in a rule passes validation here and
# then just never does anything during the scan.
POLICY_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "description": {"type": "string"},
                    "regex": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["id", "description", "regex", "severity"],
            },
        },
    },
    "required": ["name", "description", "rules"],
}


# Built in policy used when the operator supplies no policy file. The
# rules are aimed at the two shapes this tool is named for: ENV and ARG
# lines in a Dockerfile, and environment entries in a compose file.
DEFAULT_POLICY = {
    "name": "Built in Docker policy",
    "description": "Dockerfile ENV and ARG secrets, compose environment secrets, AWS access keys, and private key headers.",
    "rules": [
        {
            "id": "dockerfile-env-arg-secret",
            "description": "Dockerfile ENV or ARG line naming a secret with a value set",
            "regex": r"(?im)^[ \t]*(?:ENV|ARG)[ \t]+[A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*(?:[ \t]*=[ \t]*|[ \t]+)\S+",
            "severity": "high",
        },
        {
            "id": "compose-environment-secret",
            "description": "Compose environment entry naming a secret with a value set",
            "regex": r"(?im)^[ \t]*-?[ \t]*[\"']?[A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*[\"']?[ \t]*[:=][ \t]*[\"']?\S+",
            "severity": "high",
        },
        {
            "id": "aws-access-key",
            "description": "AWS access key ID",
            "regex": r"AKIA[0-9A-Z]{16}",
            "severity": "high",
        },
        {
            "id": "private-key-header",
            "description": "Private key header",
            "regex": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "severity": "high",
        },
    ],
}


# A match here is a real secret until I know otherwise, so nothing
# downstream ever gets the raw text. The log only needs enough of
# it for me to recognise which credential I found.
def mask_match(value):
    """Mask a matched value so a found secret is not copied into the log in full."""
    if len(value) <= 8:
        return "*" * len(value)
    # Short values get no partial reveal at all. Showing four characters
    # at each end of a nine character secret would give most of it away,
    # so the split only starts once there is a middle worth hiding.
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def validate_policy(policy):
    """
    Validates a policy against the POLICY_SCHEMA.

    Args:
        policy (dict): The policy to validate.

    Returns:
        bool: True if the policy is valid, False otherwise.
    """
    try:
        validate(instance=policy, schema=POLICY_SCHEMA)
        return True
    except ValidationError as e:
        logging.error(f"Policy validation error: {e}")
        return False


def load_policy(policy_file):
    """
    Loads a policy from a YAML or JSON file.

    Args:
        policy_file (str): The path to the policy file.

    Returns:
        dict: The loaded policy as a dictionary, or None if loading fails.
    """
    try:
        with open(policy_file, "r") as f:
            # I choose the parser from the file name, not from the contents.
            # A valid JSON policy saved as .txt is rejected below, and an
            # uppercase .YAML suffix misses this branch the same way.
            if policy_file.endswith(".yaml") or policy_file.endswith(".yml"):
                policy = yaml.safe_load(f)
            elif policy_file.endswith(".json"):
                policy = json.load(f)
            else:
                logging.error("Unsupported policy file format.  Must be YAML or JSON.")
                return None

        if not validate_policy(policy):
            return None

        return policy
    except FileNotFoundError:
        logging.error(f"Policy file not found: {policy_file}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML policy file: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON policy file: {e}")
        return None
    except Exception as e:
        logging.error(f"Error loading policy file: {e}")
        return None


def scan_file(file_path, policy):
    """
    Scans a single file for secrets based on the provided policy.

    Args:
        file_path (str): The path to the file to scan.
        policy (dict): The policy containing the regex rules.
    """
    try:
        with open(file_path, "r") as f:
            # I read the whole file as text. A binary file inside a scanned
            # directory raises on decode, lands in the generic handler below,
            # and counts as a file I could not scan rather than one I skipped.
            # That is why main can exit 1 on a tree with no secrets in it.
            content = f.read()

        for rule in policy["rules"]:
            # Custom rules get MULTILINE from this call, so a rule author does
            # not have to remember the inline flag. My built in rules carry
            # (?im) anyway because I also want case insensitivity for them.
            matches = re.finditer(rule["regex"], content, re.MULTILINE)
            for match in matches:
                # I recount the line number from the start of the file for every
                # match instead of tracking it while scanning. That is wasted work
                # on a big file, but it keeps the count right when a regex match
                # itself spans more than one line.
                logging.warning(
                    f"[{rule['severity'].upper()}] {rule['id']}: {rule['description']} - File: {file_path}, Line: {content[:match.start()].count(os.linesep) + 1}, Match: {mask_match(match.group(0))}"
                )
        return True
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return False
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")
        return False


def scan_directory(directory_path, policy):
    """
    Scans all files in a directory for secrets.

    Args:
        directory_path (str): The path to the directory to scan.
        policy (dict): The policy containing the regex rules.
    """
    errors = 0
    # This walk always goes all the way down. The recursive flag in
    # main only decides whether I call this function at all; once I am
    # in here there is no depth limit to apply.
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if not scan_file(file_path, policy):
                errors += 1
    return errors


@click.command()
@click.option(
    "--policy-file",
    "-p",
    required=False,
    default=None,
    help="Path to the policy file (YAML or JSON). If omitted, the built in Docker policy is used.",
    type=click.Path(exists=True, readable=True),
)
@click.option(
    "--target",
    "-t",
    required=True,
    help="Path to the file or directory to scan.",
    type=click.Path(exists=True, readable=True, file_okay=True, dir_okay=True),
)
@click.option(
    "--log-level",
    "-l",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Set the logging level.",
)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Recursively scan directories. If not specified directory will be scanned only on the first level.",
)
@click.version_option()
def main(policy_file, target, log_level, recursive):
    """
    madc-Docker-Secrets-Validator: Scans Dockerfiles and docker-compose.yml files for potential exposure of secrets, using a supplied policy file or, when none is supplied, the built in Docker policy.
    """
    logging.getLogger().setLevel(log_level)

    logging.info("Starting madc-Docker-Secrets-Validator...")

    # Load the policy, or fall back to the built in Docker policy
    if policy_file:
        policy = load_policy(policy_file)
        if not policy:
            logging.error("Failed to load policy. Exiting.")
            sys.exit(1)
    # Click already rejects a target that does not exist before main
    # runs, so this branch is a guard for direct calls, not a path a
    # normal command line run can reach.
    else:
        policy = DEFAULT_POLICY
        logging.info("No policy file supplied. Using the built in Docker policy.")

    # Check if the target is a file or directory
    errors = 0
    if os.path.isfile(target):
        if not scan_file(target, policy):
            errors += 1
    elif os.path.isdir(target):
        if recursive:
            errors += scan_directory(target, policy)
        else:
            # scan files within the first level of directory
            # The non recursive path lists one level and then filters to
            # files, so a subdirectory here is ignored quietly rather than
            # reported as unscanned. Anyone who needs the whole tree has to
            # ask for it with the flag.
            for file in os.listdir(target):
                file_path = os.path.join(target, file)
                if os.path.isfile(file_path):
                    if not scan_file(file_path, policy):
                        errors += 1
    else:
        logging.error(f"Invalid target: {target}")
        sys.exit(1)

    if errors:
        logging.error(f"Scanning incomplete: {errors} file(s) could not be scanned.")
        sys.exit(1)

    logging.info("Scanning complete.")


if __name__ == "__main__":
    main()


# Example Usage:
# To run the script: python madc_docker_secrets_validator.py --policy-file policy.yaml --target Dockerfile
# Create a policy.yaml file like this:
# name: "Example Policy"
# description: "Detects common secrets"
# rules:
#   - id: "hardcoded-password"
#     description: "Detects hardcoded password"
#     regex: "password = \"[^\"]*\""
#     severity: "high"
#   - id: "api-key"
#     description: "Detects API key"
#     regex: "API_KEY = \"[^\"]*\""
#     severity: "medium"

# Scan a directory recursively: python madc_docker_secrets_validator.py --policy-file policy.yaml --target ./my_project --recursive

# Scan with a specific log level: python madc_docker_secrets_validator.py --policy-file policy.yaml --target Dockerfile --log-level DEBUG