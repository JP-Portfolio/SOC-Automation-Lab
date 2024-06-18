# SOC-Automation-Lab

## Objective

The objective of this project is to demonstrate a robust Security Operations Center (SOC) automation workflow using **Wazuh and SOAR** (Security Orchestration, Automation, and Response) technologies, specifically integrating TheHive, Shuffle, and VirusTotal. This implementation showcases a proactive approach to security incident detection, response, and analysis, leveraging cloud infrastructure and automated processes to enhance the efficiency and effectiveness of threat handling.

### Skills Learned

- **Cloud Infrastructure Management**: Mastery in deploying and managing SOC tools on cloud platforms, with a focus on DigitalOcean.
- **Configuration Management**: Proficient in configuring Windows systems for security monitoring and reporting to Wazuh.
- **Workflow Automation**: Developed complex workflows in Shuffle to automate the response to security events.
- **Threat Intelligence**: Gained expertise in enriching Indicators of Compromise (IoCs) using VirusTotal and integrating findings into TheHive for alert management.
- **Active Response**: Implemented Wazuh’s active response feature to automate the mitigation of identified threats.

### Tools Used

- **Wazuh**: An open-source security monitoring solution for threat detection, integrity monitoring, incident response, and compliance.
- **TheHive**: A scalable, open-source and free Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, and CERTs.
- **Shuffle**: An open-source SOAR platform that helps automate and connect security tools for improved efficiency and effectiveness of operational security.
- **DigitalOcean**: A cloud infrastructure provider offering cloud services to help deploy modern apps.

## Steps

### Network Diagram

![SOC-LAB drawio](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/2b89247d-faf4-4f38-97fa-ca500f684ef3)

The network diagram depicts a streamlined SOAR implementation using Wazuh and Shuffle. The general overview of this project is as follows.

1. **Event Detection**: The Windows 10 client with Wazuh Agent detects a security event and sends the details to the Wazuh Manager.
2. **Event Forwarding**: The Wazuh Manager forwards the event to Shuffle for processing.
3. **IOC Enrichment**: Shuffle enriches the Indicators of Compromise (IOCs) using VirusTotal.
4. **Alert Creation**: Shuffle generates an alert and sends it to TheHive case management system with enriched information.
5. **Notification**: Shuffle sends an email notification to the SOC Analyst about the incident with major event information.
6. **User Input**: The SOC Analyst provide the input to perform response action via email.
7. **Action Execution**: Shuffle instructs the Wazuh Manager to execute a response action, such as terminating a malicious process.

This process ensures efficient and automated handling of security incidents, from detection to response.

### Wazuh and TheHive Configuration

I am using **DigitalOcean** as a cloud provider to host Wazuh and TheHive. I have created two Ubuntu VMs with following specifications: 
RAM: 8GB+<br>
HDD: 50GB+<br>
OS: Ubuntu 22.04 LTS<br>

Created firewall and added rules to allow only self-access to both VMs. 

![Screenshot 2024-06-18 181736](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/79a80dbb-b88b-4770-8c21-fd681362fb72)

#### Wazuh Installation and Configuration
_curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a_<br>
_sudo tar -xvf wazuh-install-files.tar_<br>

You will be presented with login credentials after installation. Use VM's public IP to login into Wazuh Dashboard. You can also find the login credentials in Wazuh-install-files directory. Next step is to deploy wazuh-agent on Windows Client.
1. Click drop-down menu and Select Agents. You will see list of all deployed Agents. Initially you won't find any.
2. Click Deploy New Agent and Select Windows and enter your Wazuh server IP and you will be presented with Powershell command to run on Client machine.
3. Run command as administrator and start the wazuh-service using command _NET START WazuhSvc_
4. Now the Agent will report to Wazuh Manager and you will see the active agents as shown in screenshot.

![Screenshot 2024-06-18 185906](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/229e212f-6abe-4b2d-8c56-8f8e4a9c217f)

Additionally, configure Sysmon on Windows Client using this walkthrough https://www.blumira.com/enable-sysmon/

#### TheHive Installation and Configuration

Dependencies<br>
_apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release_<br>

Install Java<br>
_wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg<br>
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list<br>
sudo apt update<br>
sudo apt install java-common java-11-amazon-corretto-jdk<br>
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment <br>
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"<br>_

Install Cassandra<br>
_wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg<br>
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list<br>
sudo apt update<br>
sudo apt install cassandra<br>_

Install ElasticSearch<br>
_wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg<br>
sudo apt-get install apt-transport-https<br>
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list<br>
sudo apt update<br>
sudo apt install elasticsearch<br>_

***OPTIONAL ELASTICSEARCH***<br>
**Follow this only if you unable to login to TheHive after making nessasary changes to the configuration!!**
_Create a jvm.options file under /etc/elasticsearch/jvm.options.d and put the following configurations in that file.<br>
-Dlog4j2.formatMsgNoLookups=true<br>
-Xms2g<br>
-Xmx2g<br>_

Install TheHive<br>
_wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg<br>
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list<br>
sudo apt-get update<br>
sudo apt-get install -y thehive<br>_

**Now to make following changes to configuration files in TheHive.**
1. Open  **/etc/cassandra/cassandra.yaml** and make following changes
   - cluster_name: 'SOC' (Choose any name or leave as it is)
   - listen_address: 146.xx.xx.xx (Change localhost to your public IP of TheHive)
   - rpc_address: 146.xx.xx.xx (Change localhost to your public IP of TheHive)
   - seeds: "146.xx.xx.xx:7000" (Change 127.0.0.1 to your public IP of TheHive)
2. Stop cassandra service using command **systemctl stop cassandra.service**
3. Remove old files using command **rm -rf * /var/lib/cassandra/***
4. Start cassandra service using command **systemctl start cassandra.service**
5. Open  **/etc/elasticsearch/elasticsearch.yml** and make following changes
   - cluster.name: thehive (Remove # and change cluster name)
   - node.name: node-1 (Remove #)
   - network.host: 146.xx.xx.xx (Remove # and add public IP of TheHive)
   - http.port: 9200 (Remove #)
   - cluster.initial_master_nodes: ["node-1"] (Remove #)
6. Start and Enable elasticsearch service using command  **systemctl start elasticsearch && systemctl enable elasticsearch**
7. Change ownership for **/opt/thp** directory to ensure user running TheHive service has appropriate permissions to read, write, or execute files in this directory using command **chown -R thehive:thehive /opt/thp**
8. Open **/etc/thehive/application.conf** and make following changes
   - hostname = ["146.xx.xx.xx"] (Change 127.0.0.1 to your public IP of TheHive)
   -  cluster-name = SOC (Should be same as of cassandra.yaml)
   -  application.baseUrl = "http://146.xx.xx.xx:9000" (Change localhost to your public IP of TheHive)
9. Start and Enable thehive service using command  **systemctl start thehive && systemctl enable thehive**
10. Check the status of each of these services (cassandra, elasticsearch and thehive) should be actively running
11. Login to TheHive at **http://Your-Hive-IP:9000** using Default Credentials 'admin@thehive.local' with a password of 'secret'

### Wazuh and TheHive Configuration
