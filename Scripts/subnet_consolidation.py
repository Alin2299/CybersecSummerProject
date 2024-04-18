# This Python script consolidates subnets for cloud providers (networks) such as AWS, and 
# writes the consolidated data into text files
# Developed by Andrew Lin, 2024

# Import the necessary modules/libraries
import ipaddress
from pathlib import Path
import os


def process_prefixes(prefix_data, file_name):
    """
    Function that takes a list of prefixes and consolidates it (I.e reduces its size),
    then writes all consolidated data to a text file

    prefix_data: The list of prefixes to be processed
    file_name: String used to help define the (final) consolidated file's name
    """ 

    # Define variables for the consolidated file's name and path
    consolidated_file_name = file_name.split("-")[0] + "-consolidated.txt"
    consolidated_file = Path(consolidation_folder / consolidated_file_name)

    # If the consolidated file already exists, display a message and return from the function
    if os.path.exists(consolidated_file):
        print(consolidated_file_name + " already exists")
        
        # Open the consolidated file so that we can print its length
        with open(consolidated_file, "r") as file:
            print("(Consolidated) Length of " + consolidated_file_name + " is: " + str(len(file.readlines())))
        return

    # Define a set for storing the consolidated prefixes
    consolidated_prefixes = set()

    # Iterate through all prefixes in the list of prefixes
    for prefix in prefix_data:

        # Checks that the prefix is not IPv6 before proceeding
        if ":" in prefix:
            continue

        # Convert the prefix string to an IPv4 network object
        network = ipaddress.ip_network(prefix, strict=False)
        
        # Check if this network is already covered by a supernet in the consolidated list
        is_subnet_of_consolidated = any(network.subnet_of(super_net) for super_net in consolidated_prefixes)
    
        if not is_subnet_of_consolidated:
            # Before adding, remove any subnets of this network from the consolidated list
            consolidated_prefixes.difference_update({n for n in consolidated_prefixes if n.subnet_of(network)})
            
            # Add this network to the consolidated list
            consolidated_prefixes.add(network)

    # Convert the set back to a list (if needed) and sort it for readability
    consolidated_prefixes = sorted(consolidated_prefixes)

    # Opens and writes all consolidated prefix data to the appropriate path/location
    with open(consolidated_file, "w") as out_file:
        for prefix in consolidated_prefixes:
            out_file.write(str(prefix) + "\n")

    # Print out the length of the consolidated file for debugging/comparison purposes
    print("(Consolidated) Length of " + consolidated_file_name + " is: " + str(len(consolidated_prefixes)))

def read_and_process(data_file):
    """
    Function that reads (prefix) data from a file and then calls another function
    to process/consolidate the data

    data_file: The file to be read and processed
    """

    # Define a list for storing the prefix data
    prefix_data = []

    # Open the file and read all prefix data into the defined list (factoring in the file type: text vs CSV)
    with open(data_file, "r") as file:
        for line in file:
            if not "csv" in file.name:
                prefix_data.append(line.strip())
            else: 
                prefix_data.append(line.split(",")[0].strip())


    # Display the length of the prefix list for debugging/comparison purposes
    print("Original length of " + data_file.name + " is: " + str(len(prefix_data)))

    # Use the function process_prefixes() to process the prefix data
    process_prefixes(prefix_data, data_file.name)
    print()


# Define the path to the folder where the consolidation data is stored
consolidation_folder = Path("Data/Subnet Consolidation")

# Iterate through each file in the overall folder and read/process any clouo provider data files (E.g AWS-ranges.txt) using read_and_process()
for file in os.scandir(consolidation_folder):
    if "consolidated" not in file.name:
        read_and_process(file)