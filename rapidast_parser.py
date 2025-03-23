import os
import argparse
import json
import csv
import sys
from datetime import datetime

def check_names(path):
    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

#Based on https://github.com/zaproxy/zaproxy/blob/296801bb838ae1ceca102a6be5b5ed2e8c29e097/src/org/parosproxy/paros/core/scanner/Alert.java#L62-L65
mapping_values = dict([
    ('0', 'Informational'),
    ('1', 'Low'),
    ('2','Medium'),
    ('3','High')
])

cwe_url = "https://cwe.mitre.org/data/definitions/{{cwe_id}}.html"
zap_url = "https://www.zaproxy.org/docs/alerts/{{alert_id}}/"

file_name = "parsed_results_" + datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + ".csv"

parser = argparse.ArgumentParser(description='Select file to parse.')
parser.add_argument('--file', dest='file',
                    default="report.json",
                    help='Select rapidast file result to parse (default: zap-report.json)')

# Default tool is 'zap', so we don't break compatibility with users using the script with default values.
parser.add_argument('--tool', dest='tool', choices=['zap', 'garak'],
                    default="zap",
                    help='Select tool whose file we want to parse')

parser.add_argument('--output', dest='output_destination',
                    default= r"results/" + file_name,
                    help='Select name of results file (the extension should be csv). If no file is specified, a default parsed_results_<date>.csv file will be used. ')

args = parser.parse_args()
f = open(args.file)

if args.tool == "zap":
    data = json.load(f)
    alerts = data['site'][0]['alerts']
    parsedalerts = []


    for alert in alerts:
        risk = mapping_values[alert['riskcode']]
        name = alert['name']
        description = alert['desc']
        solution = alert['solution']
        cwe = cwe_url.replace('{{cwe_id}}', alert['cweid'])
        instances = alert['instances']
        parsed_instances = []
        for instance in instances:
            parsed_instances.append(instance['uri'])

        confidence = mapping_values[alert['confidence']]
        zap_alert = zap_url.replace('{{alert_id}}', alert['alertRef'])

        parsed_alert = [risk,name,description,solution,cwe,parsed_instances,confidence, zap_alert]
        parsedalerts.append(parsed_alert)

    parsed_path = os.path.normpath(args.output_destination)

    check_names(parsed_path)

    with open(parsed_path, 'x', newline='') as file:
        writer = csv.writer(file)
        information = [data['site'][0]['@name'], "Port = " + data['site'][0]['@port'], "SSL = " + data['site'][0]['@ssl']]
        writer.writerow(information)
        field = ["Risk", "Name", "Description", "Solution", "CWE", "Affected Instances (Short form)", "Confidence", "Alert information"]
        writer.writerow(field)
        for elem in parsedalerts:
            writer.writerow(elem)

if args.tool == "garak":
    parsed_path = os.path.normpath(args.output_destination)

    check_names(parsed_path)

    json_list = []

    if not os.path.isfile(args.file):
        print("Specified file name does not exist")
        sys.close(1)

    with open(args.file, 'r') as jsonl_file:
        json_list = list(jsonl_file)

    with open(parsed_path, 'x', newline='') as file:
        writer = csv.writer(file)
        field = ["Goal", "Prompt", "Output", "Trigger", "Detector"]
        writer.writerow(field)
        for json_str in json_list:
            json_line = json.loads(json_str)
            goal = ""
            prompt = ""
            output = ""

            if json_line["output"]:
                parsed_output = json.loads(json_line["output"])
                for elem in parsed_output:
                    if json_line["goal"]:
                        goal = json_line["goal"].rstrip().replace("\n", "")
                    if json_line["prompt"]:
                        prompt = json_line["prompt"].rstrip().replace("\n", "")
                    output = parsed_output["response"].rstrip().replace("\n", "")
                    if json_line["trigger"]:
                        trigger = json_line["trigger"].rstrip().replace("\n", "")
                    else:
                        trigger = ""
                    if json_line["trigger"]:
                        detector = json_line["detector"].rstrip().replace("\n", "")
                        detector = "https://reference.garak.ai/en/stable/garak.detectors." + detector.split('.')[0] + \
                                   ".html" + "#garak.detectors." + detector
                    else:
                        detector = ""
                    parsed_line = [goal, prompt, output, trigger, detector]

            writer.writerow(parsed_line)
