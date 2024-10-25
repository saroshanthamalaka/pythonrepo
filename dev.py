import logging
import time
import requests

from azure.identity import ManagedIdentityCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient



# Azure clients
credential = ManagedIdentityCredential()
network_client = NetworkManagementClient(credential, "83c1c9cd-38a7-4e04-9f2e-a15cbc4ad70c")
compute_client = ComputeManagementClient(credential, "83c1c9cd-38a7-4e04-9f2e-a15cbc4ad70c")


# Configuration
resource_group = "re-rg-avd-auseast-01"  # Resource Group where Route Table exists
active_vm_resource_grp = "re-rg-avd-auseast-01"  # Resource Group where Active VM is available
passive_vm_resource_grp = "re-rg-avd-auseast-01"  # Resource Group where Passive VM is available
active_vm = "activevm"
passive_vm = "passivevm"
route_table_name = "functiontest-rtable"
active_vm_ip = "10.201.0.4"
passive_vm_ip = "10.201.0.5"

@app.schedule(schedule="0 0 */1 * * *", arg_name="timer", run_on_startup=False, useMonitor=True)
 
def main(mytimer: func.TimerRequest) -> None:
#def main(mytimer=None) -> None: # When runing locally
    logging.info('Python Timer trigger function started.')

    monitor_vms()

    logging.info('Python Timer trigger function finished.')


# Function to monitor VMs
def monitor_vms():
    is_active = True

    while True:
        if is_active:
            active_status = check_vm_status(active_vm_resource_grp, active_vm)
            if not active_status:
                print("Active VM is down. Checking Passive VM...")
                passive_status = check_vm_status(passive_vm_resource_grp, passive_vm)
                if passive_status:
                    print("Switching to Passive VM.")
                    update_route("SDWAN-10", "10.0.0.0/8", passive_vm_ip)
                    update_route("SDWAN-192.168", "192.168.0.0/16", passive_vm_ip)
                    update_route("SDWAN-172.16", "172.16.0.0/12", passive_vm_ip)

                    send_email_alert("Remondis Azure Meraki: Primary is down, failover to secondary")
                    is_active = False
                else:
                    print("Both VMs are down. Please check!")
                    send_email_alert("Remondis Azure Meraki: Both VMs are down. Please check!")
            else:
                print("Active VM is running.")
        else:
            active_status = check_vm_status(active_vm_resource_grp, active_vm)
            if active_status:
                print("Switching back to Active VM.")
                time.sleep(60)
                update_route("SDWAN-10", "10.0.0.0/8", active_vm_ip)
                update_route("SDWAN-192.168", "192.168.0.0/16", active_vm_ip)
                update_route("SDWAN-172.16", "172.16.0.0/12", active_vm_ip)

                send_email_alert("Remondis Azure Meraki: Primary is back online and route has been updated")
                is_active = True
            else:
                print("Primary is still down.")

        time.sleep(180)  # Sleep for a defined interval before the next check



# Function to send email alert via ACS
def send_email_alert(message):
    email_subject = "Remondis Azure Meraki: Meraki Firewall Failover Notification"
    email_recipient = "roshan.thamalaka@secureagility.com"
    resource_id = "https://communication.azure.com"
    communication_endpoint_url = "https://tstcommserviceusa.unitedstates.communication.azure.com"

    # Get access token from Managed Identity
    access_token = credential.get_token(resource_id).token

    # Set up the email sending API endpoint
    uri = f"{communication_endpoint_url}/emails:send?api-version=2023-03-31"

    # Prepare the email payload
    api_response = {
        "senderAddress": "DoNotReply@b44f1b49-4bc4-4760-a79d-20880ef47289.azurecomm.net",
        "recipients": {
            "to": [{"address": email_recipient}]
        },
        "content": {
            "subject": email_subject,
            "plainText": message
        }
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    # Send the email
    try:
        response = requests.post(uri, json=api_response, headers=headers)
        response.raise_for_status()
        print(f"Email sent: {message}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send email: {e}")

# Function to check VM status
def check_vm_status(vm_rg, vm_name, retry_count=3, retry_delay=10):
    attempt = 0
    while attempt < retry_count:
        try:
            vm = compute_client.virtual_machines.instance_view(vm_rg, vm_name)
            statuses = [s.code for s in vm.statuses]
            if 'PowerState/running' in statuses:
                return True
            return False
        except Exception as e:
            print(f"Attempt {attempt + 1}: Failed to get VM status due to exception. Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
            attempt += 1
    raise Exception(f"Failed to get VM status after {retry_count} attempts.")

# Function to update the route
def update_route(route_name, address_prefix, new_ip):
    # Get the route table
    route_table = network_client.route_tables.get(resource_group, route_table_name)

    # Find and update the specific route by name
    route = next((r for r in route_table.routes if r.name == route_name), None)
    if route:
        route.address_prefix = address_prefix
        route.next_hop_ip_address = new_ip
        network_client.route_tables.begin_create_or_update(resource_group, route_table_name, route_table)
        print(f"Route '{route_name}' updated with AddressPrefix '{address_prefix}' and NextHopIpAddress '{new_ip}'")

