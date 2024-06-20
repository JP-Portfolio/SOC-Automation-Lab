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
6. **User Input**: The SOC Analyst provides the input to perform response action via email.
7. **Action Execution**: Shuffle instructs the Wazuh Manager to execute a response action, such as terminating a malicious process.

This process ensures efficient and automated handling of security incidents, from detection to response.

### Wazuh and TheHive Configuration

I am using **DigitalOcean** as a cloud provider to host Wazuh and TheHive. I have created two Ubuntu VMs with the following specifications: 
RAM: 8GB+<br>
HDD: 50GB+<br>
OS: Ubuntu 22.04 LTS<br>

Created a firewall and added rules to allow only self-access to both VMs. 

![Screenshot 2024-06-18 181736](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/79a80dbb-b88b-4770-8c21-fd681362fb72)

#### Wazuh Installation and Configuration
_curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a_<br>
_sudo tar -xvf wazuh-install-files.tar_<br>

You will be presented with login credentials after installation. Use the VM's public IP to log into the Wazuh Dashboard. You can also find the login credentials in Wazuh-install-files directory. The next step is to deploy wazuh-agent on Windows Client.
1. Click the drop-down menu and Select Agents. You will see a list of all deployed Agents. Initially, you won't find any.
2. Click Deploy New Agent, Select Windows, and enter your Wazuh server IP, and you will be presented with the Powershell command to run on the Client machine.
3. Run the command as administrator and start the wazuh-service using the command _NET START WazuhSvc_
4. Now the Agent will report to the Wazuh Manager, and you will see the active agents as shown in the screenshot.

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

### Sysmon Log Ingestion in Wazuh

By default, Wazuh doesn't log Symon events. To do so we need to make changes in the **ossec.conf** configuration file on Wazuh-Cleint and Wazuh-Manager.
1. On Windows client configure Wazuh-agent to send all the sysmon related events to Wazuh-Manager **C:\Program Files (x86)\ossec-agent\ossec.conf**. After making changes, restart the Wazuh service on the client.

![Screenshot 2024-06-19 183502](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/bf7ae66f-a55e-4f8d-96a4-fec6abf693ab)

2. On Wazuh-Manager make following changes to **/var/ossec/etc/ossec.conf**

![Screenshot 2024-06-19 184457](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/baa60475-cfb8-4f53-9945-c0026bb0377c)

3. On Wazuh-Manager open **/etc/filebeat/filebeat.yml**, which is a service designed to collect and forward log data to central processing and storage systems, such as Elasticsearch, Logstash, or other log management solutions and make following changes: It will send all the logs to Wazuh.

![Screenshot 2024-06-19 184457](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/3a11ae6e-e2ad-4678-8ea0-28cd0b98daaf)

4. Restrat the wazuh.manger and filebeat services using command: **systemctl restart wazuh-manager.service && systemctl restart filebeat**
5. Open Wazuh Dashboard and create and select new index pattern **(Stack Management > Index Patterns > Create Index Pattern)**

![Screenshot 2024-06-19 190317](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/c4646ebb-ec06-4b43-a760-fe3a826e14e0)
![Screenshot 2024-06-19 190336](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/30a9a380-3522-4518-981f-fc6be96eaff9)
![Screenshot 2024-06-19 190504](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/6d4ab627-b3c9-477f-b16e-9fb5ba6c2155)

5. Create a custom rule to detect Mimikatz!! Locate the **local_rules.xml** file (all the custom rules are stored in this file) and add the following rule:

![Screenshot 2024-06-19 191718](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/c64fae98-eb9e-4a6b-8115-5c92416f6791)
![Screenshot 2024-06-19 191343](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/06e6b8d9-eddc-48ec-9503-f6a0b17de200)

_The **OriginalFileName** field is derived from the PE (Portable Executable) header of the file. This field is particularly useful for security monitoring and incident response, as it can help identify malicious processes even if they are masquerading as legitimate system processes by using the same process name. For example, if we change the name of a Mimikatz executable to avoid detection, the OriginalFileName field can still help reveal the process’s true identity._

6. Test the rule!! To see the effectiveness of rule I already change the executable name.

![Screenshot 2024-06-19 193104](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/2ae6cb8c-729e-4d1a-972c-2d335d8f0603)
![Screenshot 2024-06-19 193155](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/741849af-a5b7-48d6-9866-fa8a27a353a4)

### SOAR Implementation using Shuffle

1. Create a Shuffle account and new workflow with appropriate Name, Description and Usaecase. https://shuffler.io/workflows
2. Select the **Webhook** triggr and name it to Wazuh-Alert. Copy the Webhook URI, which is requires to integrate Shuffle with Wazuh.

![Screenshot 2024-06-19 194606](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/1a149016-9957-4160-bd39-5232f4cd016a)

3. Open the **/var/ossec/etc/ossec.conf** file on Wazuh-Manager and make following changes to integrate shuffle:

![Screenshot 2024-06-19 193858](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/f9411bcb-e181-464c-a68c-64fc0c8ea7f6)

4. Start the Webhook and run Mimikatz again to check if we get alert on Shuffle:

![Screenshot 2024-06-19 195652](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/f65bfff7-cb85-4547-bea4-ac9fc497f2c1)

5. We successfully got Alert on Shuffle..Next, we will extract the SHA256 hash from the event data. Click on Change Me and rename it to **SHA256-regex**. Change Find Actions to **Regex Capture Group**. Input following Regex to parse hash: **SHA256=([A-F0-9]+)**. Select Input Data to point the hash values from the event field as below and save the workflow.

![Screenshot 2024-06-19 200352](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/2dfa66a3-9178-4916-846a-42c70ae84ec7)

6. Rerun the workflow by clicking Explore Runs to check our configuration. Looks like we got our SHA256 Hash successfully.

![Screenshot 2024-06-19 200547](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/3e58cf65-f1d8-4904-ae82-53c159a26bc6)

7. In the next stage we will enrich our hash using Virustotal App. For that select **Virustotal** App from the search and do following changes: You will need to paste your API key from Virustotal for authentication. If everything is configured correctly we will get a hash report from the Virustotal for our extracted hash.

![Screenshot 2024-06-19 202008](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/8f0ccaf9-ae1f-4322-869a-265b78dfc1fb)

8. Save and Rerun the workflow. The following Image shows the expected output if everything is configured correctly.

![Screenshot 2024-06-19 202931](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/ac94933d-6145-4b00-89be-b3bf6b222709)

9. Next is to configure Shuffle to create a custom alert in **TheHive** with our enriched information. For that login to TheHive web gui and creat a new organisation with 2 users: One is **Analyst** and other is **Service Account**. Copy the Service Account API key to Authenticate with Shuffle.

![Screenshot 2024-06-19 203324](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/10d9894c-e127-4dbd-aa59-5fd8bf152170)

10. Next, select **TheHive** application into the workflow and click + icon to setup authentication as below: _(Replace the IP address and API key)_

![Screenshot 2024-06-19 204120](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/88c7c155-e831-4dfe-95c4-341401935152)

11. Select the **Create Alert** under the find actions and do following changes: _(You can select and customize what information you need in alert)_
    - Type: Alert
    - Tlp: 2
    - Title: Title: $exec.title
    - Tags: ["$exec.text.win.eventdata.ruleName"] _(Require to put in array otherwise gives error)_
    - Summary: \n* ProcessID:$exec.text.win.eventdata.processId \n* FilePath: $exec.text.win.eventdata.commandLine \n* Detected Malicious by $virustotal.#.body.data.attributes.last_analysis_stats.malicious AV
    - Status: New
    - Sourceref: $exec.rule_id
    - Source: Wazuh
    - Severity: 2
    - Pap: 2
    - Flag: Null
    - Externallink: Null
    - Description: Mimikatz Detected! \n* Host: $exec.text.win.system.computer \n* Timestamp:$exec.text.win.eventdata.utcTime \n* File_Name:$exec.text.win.eventdata.originalFileName

12. Save and Rerun workflow and check if new alert is created in TheHive.. **_(Login to TheHive as a newly created Analyst user)_**

![Screenshot 2024-06-19 210104](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/c7bf6cf3-f64a-459c-b16d-7b19d21b129e)

13. Similarly, we will send the alert notification via email to the analyst with critical alert information. Select the Email App from the search and enter recipient email, subject and body. Save and Rerun the workflow and check email inbox for notification. **_(Select and customize Information to sent in body such as User or Computer name and Timestamp of event)_.**

![Screenshot 2024-06-19 211058](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/6a28038d-dc39-428a-86f8-d011441f2025)

14. As a final step in the lab, we will configure an active response to the kill process related to the Mimikatz application using Wazuh API in Shuffle. _**(Active response in Wazuh refers to automated actions taken in response to security events, such as blocking IP addresses or executing scripts based on predefined rules.)**_ To do so, we need to authenticate Wazuh using an API token. To get that token, we will utilize a curl command that retrieves the JWT token (JSON Web Token). This token will be used to execute an active response command from Shuffle. Select **HTTP** application from the search and paste the following curl command and make sure to replace IP address of Wazuh, username and password. All the credentials are found in the file **/root/wazuh-install-files/wazuh-passwords.txt**. The expected output is shown in the screenshot.
    
    - **curl -u USERNAME:PASSWORD -k -X GET "https://WAZUH-IP:55000/security/user/authenticate?raw=true"**

![Screenshot 2024-06-20 163220](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/56b939d3-4f28-4593-9255-10cbb87414c3)

15. Select **User Input trigger** from the search and make the following changes: It will send an email to the Analyst if He/She wants to kill the process related to MimiKatz. Based on the selected Input, Wazuh will send the active response command. 

![Screenshot 2024-06-20 163803](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/ab53874c-0440-4b10-a378-f11ffe60257e)

16. On Wazuh-Manager make following changes to **/var/ossec/etc/ossec.conf** for active response. By default, Wazuh provides some built-in active response commands, but we have to specify which commands or scripts should be executed when specific events occur. In our example, the active response configuration is set up to execute the **block.bat** script when rule ID 100002 is met.

![Screenshot 2024-06-20 164907](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/48e51152-53bc-4414-b4d5-bbbe80b6aea8)

17. Configure **Wazuh API** in Shuffle to send the active response command **(block)**. Select Wazuh app from the search and make following changes: _(Find Actions, API key, URL, Agent list, command and Arguments if any)_

![image](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/90d22d22-6018-4172-8817-6ed0dc586612)

18. Final workflow design and execution.
    - Start the webhook and run Mimikatz on the Windows Client.
    - The custom rule (100002) that we created will trigger, and an alert will be received in Shuffle.
    - The SHA256 Hash related to Mimikatz will be parsed and fed into Virustotal.
    - The Hash report will be generated, and a custom alert will be created into TheHive for analysts to investigate.
    - Additionally, an email notification will be sent to the Analyst with a high-level summary of an event.
    - The analyst will be asked to provide user input to kill the process.
    - Based on the user input, an active response command **(block)** will be executed, and the Mimikatz-related process will be terminated.

![Screenshot 2024-06-20 172947](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/b10fcbd9-81e2-464d-a9fe-b127872ce1bd)
![Screenshot 2024-06-20 173055](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/3843e385-49e6-47a8-ba50-37dab4969782)
![Screenshot 2024-06-20 174701](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/131c6589-a525-4008-a266-f34ff9bf03f9)
![Screenshot 2024-06-20 173511](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/4e7aa866-6d2c-4da7-af4d-ae8227cd4cec)
![Screenshot 2024-06-20 173616](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/e96bba4d-e943-4538-9ec8-908ef9f5092c)
![Screenshot 2024-06-20 174008](https://github.com/JP-Portfolio/SOC-Automation-Lab/assets/167912526/2606f8d0-2827-46df-b892-693b9f6c0ee9)









 
