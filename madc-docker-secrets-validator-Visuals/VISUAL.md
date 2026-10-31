# Madc Docker Secrets Validator in pictures

Five sheets, drawn by hand from the files in this repo as they sat on 2026-10-30. Every number below was counted from that local snapshot, not copied from anywhere. Where a sheet could not say something true, it says less.

## The sheets

- architecture.png and architecture.svg: the put-together. The biggest file sits at the top, the files under it are the next largest, and the names listed are real function or class names read out of the source.
- flowchart.png and flowchart.svg: the run. Start at the entry file, pass through the real steps the code takes, end where the code ends.
- product-map.png and product-map.svg: what the project is for, what goes in, what comes out, and where it stops. The stop card matters as much as the rest.
- data-flow.png and data-flow.svg: the data path in one direction, file to result.
- statistics.png and statistics.svg: the counts, drawn as bars you can check against the repo.

## How the numbers were counted

Lines of code were counted file by file from the snapshot, grouped by the language each extension belongs to. Commit counts and dates came from the local git log of the snapshot. Test files are files with test or spec in the name. If a count could not be made from the snapshot, the sheet leaves it out instead of guessing.

## The paper rule

The sheets are drawn on notebook paper with three binder holes down the left side. Nothing is ever drawn over a hole: the layout keeps every letter, box, and arrow clear of the holes with room to spare, and a machine check counts ink inside the hole zones on every sheet. This set scored 0 ink pixels in the hole zones, which is the only score that passes.

## The PDF

madc-docker-secrets-validator-Visuals.pdf holds the five finished sheets as pages, in the order above, for printing or sending without the folder.
