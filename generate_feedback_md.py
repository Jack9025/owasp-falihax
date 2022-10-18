#!/usr/bin/env python3

"""
generate_feedback_md.py
=======================
Generates a FEEDBACK.md markdown document from a feedback.json file.

Copyright CyberSoc (c) October 2022.
"""

import json
import requests
from urllib.parse import urljoin
import os
from itertools import chain

# which code file extensions map to which github markdown highlighter?
markdown_highlighting = {".py" : "python"}

mark_scheme = [
                # state, show, demo, describe mitigate, attempt fix, fix works, explain fix
                {
                    "tick": 0b1000000,
                    "dash": 0b0000011,
                    "marks": 1
                },
                {
                    "tick": 0b1100000,
                    "dash": 0b0000011,
                    "marks": 2
                },
                {
                    "tick": 0b1010000,
                    "dash": 0b0100011,
                    "marks": 3
                },
                {
                    "tick": 0b1001000,
                    "dash": 0b0110011,
                    "marks": 4
                },
                {
                    "tick": 0b1000100,
                    "dash": 0b0111001,
                    "marks": 4
                },
                {
                    "tick": 0b0000110,
                    "dash": 0b1101000,
                    "marks": 5
                },
                {
                    "tick": 0b0010110,
                    "dash": 0b1101000,
                    "marks": 6
                },
                {
                    "tick": 0b0000111,
                    "dash": 0b1111000,
                    "marks": 7
                }
               ]

def get_things_done(found) -> int:
    return (found['marks']['state'] << 6) + \
                    (found['marks']['show'] << 5) + \
                    (found['marks']['demo'] << 4) + \
                    (found['marks']['mitigate'] << 3) + \
                    (found['marks']['attempt'] << 2) + \
                    (found['marks']['works'] << 1) + \
                    (found['marks']['explain'])

def get_mark(found, maximum_mark=None) -> int:
    things_done = get_things_done(found)
    mark = 0 
    for possible_mark in mark_scheme:
        if (things_done & ((0b1111111)-(possible_mark['dash'])) == possible_mark['tick'] & ((0b1111111)-(possible_mark['dash']))) and (things_done | possible_mark['dash'] == possible_mark['tick'] | possible_mark['dash']):
            mark = possible_mark['marks']
    return mark if maximum_mark is None else min(mark, maximum_mark)

def fetch_feedback_json() -> dict:
    f = open('feedback.json')
    j = json.loads(f.read())
    f.close()
    return j

def fetch_vulns_json() -> dict:
    j = None
    if os.path.exists('vulns.json'):
        f = open('vulns.json')
        j = json.loads(f.read())
        f.close()
    else:
        j = json.loads(requests.get("https://raw.githubusercontent.com/CyberSoc-Newcastle/owasp-falihax/main/vulns.json").text)
    return j

def get_instance_ids(vulns: dict) -> dict:
    instance_ids_ = {}
    next_misc_qualifier = 1
    for category in vulns['categories']:        
        qualifier = ""
        if 'owasp-id' in category:
            qualifier = category['owasp-id']
        else:
            qualifier = f"B{str(next_misc_qualifier).zfill(2)}"
            next_misc_qualifier += 1
        if 'instances' in category:
            for instance in enumerate(category['instances'], start=1):
                instance_ids_[qualifier + "-" + str(instance[0]).zfill(2)] = {'name': instance[1]['name'], 'maximum_mark': category['maximum_mark'] if 'maximum_mark' in category else None}
    return instance_ids_

def render_found(found: dict) -> dict:
    output = f"### [{found['id']}: {instance_ids[found['id']]['name']}](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#{anchorise(found['id']+': '+instance_ids[found['id']]['name'])})\n"
    mark = get_mark(found, instance_ids[found['id']]['maximum_mark'])
    things_done = get_things_done(found)
    if instance_ids[found['id']]['maximum_mark']:
        output += f"*Maximum mark of {instance_ids[found['id']]['maximum_mark']} for this category*\n"
    output += table([chain((("✔" if (things_done >> (6-thing)) & 1 else "❌") for thing in range(7)), str(mark))], ["State", "Show", "Demo", "Mitigate", "Attempt fix", "Fix works", "Explain fix", "Mark"])
    if 'note' in found and found['note']:
        output += f"{found['note']}\n\n"
    return {'output': output, 'mark': mark}

def render_additional(additional: list) -> str:
    output = ""
    for this_additional in additional:
        output += f"### {this_additional['name']}\n"
        output += f"{this_additional['description']}\n\n"
        output += f"*+1 bonus mark awarded.*\n\n"
    return output

def anchorise(heading: str) -> str:
    return heading.lower().replace(" ", "-").replace(":", "").replace("\"", "").replace("(", "").replace(")", "")

def table(rows_: iter, headings_: iter):
    rows = list(list(row) for row in rows_)
    headings = list(headings_)
    output = "| " + (" | ".join((heading[1].center(max(len(list(row)[heading[0]]) for row in rows)) for heading in enumerate(headings)))) + " |\n"
    output += "|-" + ("-|-".join(("-"*len(heading[1].center(max(len(list(row)[heading[0]]) for row in rows)))) for heading in enumerate(headings))) + "-|\n"
    output += "\n".join(
            (
                "| " + " | ".join((
                    cell[1].ljust(len(headings[cell[0]]))
                ) for cell in enumerate(row)) + " |") for row in rows
        )
    output += "\n\n"
    return output

if __name__ == '__main__':
    feedback = fetch_feedback_json()
    vulns = fetch_vulns_json()
    global instance_ids
    instance_ids = get_instance_ids(vulns)
    user = feedback['repo'].split('/')[0]
    rendered = list(render_found(found) for found in feedback['found_vulns'])
    final_mark = sum(found['mark'] for found in rendered) + (len(feedback['additional']) if 'additional' in feedback else 0)
    output = f"\n[comment]: # (Generated from JSON file by {os.path.basename(__file__)})\n"
    output += "[comment]: # (Intended to be read in GitHub's markdown renderer. Apologies if the plaintext formatting is messy.)\n\n"
    output += f"# {user}'s OWASP Falihax Hackathon Feedback\n"
    output += f"*Marked by [CyberSoc](https://cybersoc.org.uk/?r=falihax-marking-{user.lower()})*\n\n"
    output += f"This is {user}'s specific feedback. See below for the full vunerability list, including ones you may have missed.\n\n"
    output += f"[General hackathon feedback with full vulnerability list and solutions](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md)\n"
    output += "## Summary\n"
    output += f"**Total mark:** {final_mark}\n\n"
    output += feedback['summary'] + "\n\n"
    output += "## Marking Scheme Used\n"
    output += "We used the following marking scheme to award marks for each vulnerability, where the mark awarded for the vulnerability is the highest row in the following table fulfilled by your solution. A tick means you had to have done this to get the mark, a cross means this mark does not apply if you did this, and a dash means this is ignored for this possible mark. This mark scheme was decided after the entries had been submitted and was not known to entrants during the competition, although hints were provided as to what to include for good marks.\n\n"
    output += "For each vulnerability, this is how many marks we would award:\n"
    output += (table((chain((("-" if (possible_mark['dash'] >> (6-thing)) & 1 else ("✔" if (possible_mark['tick'] >> (6-thing)) & 1 else "❌")) for thing in range(7)), [str(possible_mark['marks'])]) for possible_mark in mark_scheme), ["State a valid vulnerability", "Show where it is in code", "Demo it", "Describe how it could be mitigated", "Attempt a reasonable fix", "Fix works", "Explain your fix", "Marks"]))
    output += "## Vulnerabilites Found\n"
    output += "\n".join(found['output'] for found in rendered)
    if 'additional' in feedback:
        output += "## Bonus marks\n"
        output += "Bonus marks were awarded for great non-security critical things that really stood out to us, specific to your project. Each entry below gets you one bonus mark.\n\n"
        output += render_additional(feedback['additional'])
    output += "## Total mark\n"
    output += f"{' + '.join(chain((str(found['mark']) for found in rendered), ('1' for _ in range(len(feedback['additional']) if 'additional' in feedback else 0))))} = {final_mark}\n\n"
    output += f"**Your total mark is {final_mark}**"
    f = open('FEEDBACK.md', 'wb')
    f.write(output.encode('utf-8'))
    f.close()
    print("Done.")
