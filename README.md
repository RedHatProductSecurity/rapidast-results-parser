# Rapidast Results Parser

This small python script is used in order to generate a .csv file that will help the offering teams to intrepet the Rapidast results

## Usage

The usage is very simple, just run the script with `--file` as argument: 

```
python3 rapidast_parser.py --file zap-report.json
```

## GitHub Actions

In order to simplify the use of the script, we also provide a GitHub action that can be integrated into your repo to perform the parsing of the files automatically.
In order to make it work, you will need to use a token with write access and modify the secret name under the line

```
token: ${{secrets.GH_TOKEN}}
```

This action will create a new folder in your repo called `results` where these files will be uploaded. If you want to change the path, just use the `--output` parameter and specify it.

## Disclaimer

In order to avoid discolosing sensitive information, the instances columns just show the endpoint but won't show any header. To see this information, look at the original results file.

