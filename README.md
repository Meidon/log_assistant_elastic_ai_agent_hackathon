# Log Assistant

## Overview

Log Assistant is a tool designed to help you quickly analyze and debug logs and metrics from your elastic environment. It provides a concise overview of the situation and suggests fixes for identified issues, saving you time and effort.

## Features

- **AI-Driven Analysis**: Leverages AI to provide quick insights and suggestions.
- **2 Workflows**: to get started with calling your AI agent 1 manual, 1 scheduled, modify at your own discresion.
- **Pattern Analysis**: Identifies patterns in logs and metrics for better understanding.
- **Anomaly Detection**: Looks for unusual activity in your metric or logs
- **Correlation**: Looks for similarities and patterns in your metrics and logs (that you've specified) within the time range and checks if there is a correlation. 


## Getting Started

### Prerequisites

- Elasticsearch
- Kibana
- PowerShell
    (for generating fake data) or your preferred language you don't have to use the synthetic data generator provided just use your own if that is easier.
- Local or Cloud hosted LLM
    (I used devstral24bv2 but you can try with your own model and check how good it integrates with Elastic)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/log-assistant.git
   ```

2. Start up your Elastic instance:

3. Configure the environment:
   Copy over the AI-Tools and Instruct for your AI Agent
   Setup your indexes with log data and metrics
   Don't forget to fire up your LLM and setup the connector (instructions here may wary depending on your provider)
   https://www.elastic.co/docs/deploy-manage/manage-connectors

   I used the Other (OpenAI Compatible Connector) as my setup had a forwarded endpoint the LLM was listening to 

4. Run the Log Assistant

## Powershell script
If you end up using the fake data generator please modify the script variables

# Configuration
$esURL = "https://<your_elasticsearch_url_here>:<your_port_here>"

# Log indices
$logsWindowsIndex = "<your_windows_log_index_here>"
$logsMainframeIndex = "<your_mainframe_log_index_here>"
$logsApplicationIndex = "<your_application_log_index_here>"
$logsPowershellIndex = "<your_powershell_log_index_here>"
# Performance metrics indices
$perfAppTransIndex = "<your_application_transactions_metric_index_here>"
$perfWindowsIndex = "<your_windows_metric_index_here>"
$perfMainframeIndex = "<your_mainframe_metric_index_here>"
$SleepInterval = 10 # The inbetween sleep timer for batches in seconds
$PerfSampleInterval = 60 # How quickly it should generate another batch of performance metrics in seconds
$LogsSampleInterval = 60 # How quickly it should generate another batch of logs in seconds
# Credentials (Basic Auth)
$username = "<your_username_here>"
$password = "<your_password_here>"

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the Elastic community for their support and resources and Elastic themselves for their great software.
