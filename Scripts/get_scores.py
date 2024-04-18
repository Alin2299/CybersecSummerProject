# This Python script processes structured Censys-collected data and generates a "scores" file for each 
# date/country combination
# Developed by Andrew Lin 2023/2024, with some code from Bruce Parkinson

# Import the necessary libraries/packages
import os
import tarfile
from pathlib import Path
import shutil
import re
import os.path
import subprocess

def extract_tar(tgz_path, dest_path):
    """
    Function that extracts a tgz file using command-line tools through subprocess

    tgz_path: The path to the tgz file to be extracted
    dest_path: The path to the extraction destination
    """
    # Creates the extraction destination if it doesn't already exist, then use subprocess to run the tar extraction command
    dest_path.mkdir(parents=True, exist_ok=True)
    subprocess.run(['tar', '-xzf', str(tgz_path), '-C', str(dest_path)], check=True)

def calculate_scores(sockets_file, results_folder, scores_file):
    """
    Function that calculates scores for targets based on security factors such as TLS version
    and writes the score data to text files
    DISCLAIMER: Most of this function was developed by Bruce Parkinson, with minor modifications made by me
    
    sockets_file: File that contains data about all unique scanned targets/sockets
    results_folder: Folder containing scan data results as txt files
    scores_file: Path to the scores file
    """
    # Define a temporary string for storing the lines data for writing efficiency
    scores_string = ""

    # Define a list for storing the sockets, then open the sockets file and append all data into the list
    sockets = []
    with open(sockets_file) as f:
        for line in f:
            sockets.append(line.split())

    # Iterate through all sockets
    for i in sockets:
        dhFile = results_folder+"/"+i[0]+"-"+i[1]+"-"+"dh-params.txt"
        hbFile = results_folder+"/"+i[0]+"-"+i[1]+"-"+"heartbleed.txt"
        sslv2File = results_folder+"/"+i[0]+"-"+i[1]+"-"+"sslv2.txt"
        resultsFile = results_folder+"/"+i[0]+"-"+i[1]+".txt"

        #    print(dhFile)
        #    print(hbFile)
        #    print(sslv2File)
        #    print(resultsFile)

        # if not os.path.exists(dhFile):
        #     print(dhFile)
            
        # if not os.path.exists(hbFile):
        #     print(hbFile)
            
        # if not os.path.exists(sslv2File):
        #     print(sslv2File)
            
        # if not os.path.exists(resultsFile):
        #     print(resultsFile)
        
        # Define variables for the score and factors/reasons that contribute to the score
        score = 1
        reasons = ""

        # Try block for catching errors (specifically when certain data files are not found)
        try:
        # Check for weak DH key negotiation
            with open(dhFile) as f:
                dhString = f.read().replace('\n', ' ')
                if re.search("State: VULNERABLE", dhString):
                    score = max (score, 3)
                    reasons = reasons + "Weak DH;"

        # Check for HeartBleed vulnerability
            with open(hbFile) as f:
                hbString = f.read().replace('\n', ' ')
                if re.search("State: VULNERABLE", hbString):
                    score = max (score, 6)
                    reasons = reasons + "Heartbleed;"

        # Check for SSLv2 support
            with open(sslv2File) as f:
                sslv2String = f.read().replace('\n', ' ')
                if re.search("SSLv2 supported", sslv2String):
                    score = max (score, 6)
                    reasons = reasons + "SSLv2;"

            with open(resultsFile) as f:
                resultsString = f.read().replace('\n', ' ')
        #        print(resultsString)
        # Filtered - target didn't respond, score as 100
        #        if re.search("filtered", resultsString):
        #            score = max (score, 100)
        #            reasons = reasons + "Filtered - host did not respond to probing attempt"
        # Open - target didn't respond as expected, score as 100
        #        if re.search("tcp open ", resultsString):
        #            score = max (score, 100)
        # ssl-enum-ciphers script didn't return results - not scanned?
                if not re.search("ssl-enum-ciphers:", resultsString):
                    score = max (score, 100)
                    reasons = reasons + "No result from ssl-enum-ciphers script logged"
        # Protocol Support
                if re.search("SSLv3:", resultsString):
                    score = max (score, 6)
                    reasons = reasons + "SSLv3;"
                if re.search("TLSv1.0:", resultsString):
                    score = max (score, 3)
                    reasons = reasons + "TLSv1.0;"
                if re.search("TLSv1.1:", resultsString):
                    score = max (score, 3)
                    reasons = reasons + "TLSv1.1;"
        # Compression Support
                if re.search("DEFLATE", resultsString):
                    score = max (score, 3)
                    reasons = reasons + "Compression;"
        # Key Exchange
                if re.search("TLS_RSA_", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "RSA doesn't offer PFS;"
                if re.search("TLS_ECDH_RSA_", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "ECDH_RSA doesn't offer PFS;"
                if re.search("TLS_ECDH_ECDSA_", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "ECDH_ECDSA doesn't offer PFS;"
                if re.search("_PSK", resultsString):
                    score = max (score, 3)
                    reasons = reasons + "PSK doesn't offer PFS and susceptible to brute force;"
        # Authentication
                if re.search("DH_anon", resultsString):
                    score = max (score, 6)
                    reasons = reasons + "Anon authentication;"
                if re.search("TLS_NULL_", resultsString):
                    score = max (score, 6)
                    reasons = reasons + "NULL authentication;"
        # Ciphers
                if re.search("_CBC_", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "CBC mode;"
                if re.search("SEED", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "SEED cipher;"
                if re.search("CAMELLIA", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "CAMELLIA cipher;"
                if re.search("IDEA", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "IDEA cipher;"
                if re.search("ARIA", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "ARIA cipher;"
                if re.search("RC2", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "RC2 cipher;"
                if re.search("RC4", resultsString):
                    score = max (score, 3)
                    reasons = reasons + "RC4 cipher;"
                if re.search("_WITH_NULL_", resultsString):
                    score = max (score, 6)
                    reasons = reasons + "NULL cipher;"
                if re.search("EXPORT", resultsString):
                    score = max (score, 6)
                    reasons = reasons + "EXPORT cipher;"
                if re.search("_WITH_DES", resultsString):
                    score = max (score, 6)
                    reasons = reasons + "DES cipher;"
                if re.search("_WITH_3DES_", resultsString):
                    score = max (score, 6)
                    reasons = reasons + "3DES cipher;"
        # MAC
                if re.search("MD5", resultsString):
                    score = max (score, 3)
                    reasons = reasons + "MD5 MAC;"
        # Other checks
        #
        # Client cipher preference
                if re.search("cipher preference: client", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "Client cipher prefer;"
                if re.search("cipher preference: indeterminate", resultsString):
                    score = max (score, 2)
                    reasons = reasons + "Indeterminate cipher prefer;"

        # Good things, that get recorded but don't downgrade the score
                if re.search("TLS_AKE", resultsString):
                    reasons = reasons + "**TLS_AKE**;"
                if re.search("DHE", resultsString):
                    reasons = reasons + "**DHE**;"
                if re.search("AES", resultsString):
                    reasons = reasons + "**AES**;"
                if re.search("CHACHA20_POLY1305", resultsString):
                    reasons = reasons + "**CHACHA20_POLY1305**;"
                if re.search("TLSv1.2", resultsString):
                    reasons = reasons + "**TLSv1.2**;"
                if re.search("TLSv1.3", resultsString):
                    reasons = reasons + "**TLSv1.3**;"


        # If score < 10 (ie, there is data for that particular target and Nmap didn't return "filtered") then print the result for this record
        #    if score < 10:
        #        print(i[0] + "," + i[1] + "," + str(score) + "," + reasons)
            # print(i[0] + "," + i[1] + "," + str(score) + "," + reasons)

            # Write the socket and its associated score and reasons to the scores file
            # with open(scores_file, "a") as file:
            #     file.write(i[0] + "," + i[1] + "," + str(score) + "," + reasons + "\n")
            
            # Append the appropriate information to the scores string
            scores_string += i[0] + "," + i[1] + "," + str(score) + "," + reasons + "\n"
        
        # Print an error message if a data file was not found
        except FileNotFoundError as e:
            print(e.filename + " not found")

    # Write the entire final scores string to the file
    with open(scores_file, "a") as file:
        file.write(scores_string)


# Guards the script from accidental execution 
if __name__ == "__main__":

    # Specify paths to the data, including sockets data
    au_data_path = "Data/Sample Data/AU"
    nz_data_path = "Data/Sample Data/NZ"
    socket_data_path = "Data/Sample Data/targets"

    # Iterate through all Australian data folders such as au-20230518
    for au_date_folder in os.scandir(au_data_path):

        # Checks that the folder is actually a proper folder before proceeding
        if not au_date_folder.is_dir() or au_date_folder.name == "CensysJSON":
            continue

        # Define the path to where the scores file should be placed
        scores_file = Path(au_data_path + "/" + au_date_folder.name +"-scores.txt")

        # If the scores file for the given folder already exists, simply move onto the next folder
        if os.path.exists(scores_file):
            print(str(scores_file) + " already exists")
            continue
        
        # Get all (thread) tgz files to be extracted
        tgz_files = list(Path(au_date_folder.path).rglob("*.tgz"))

        # Iterates and processes/extracts all tgz files
        for tgz_file in tgz_files:
            # Define a (temporary) folder for extraction
            temp_folder_name = tgz_file.name.replace(".tgz", "")
            temp_folder = Path(os.path.join(au_data_path, au_date_folder.name, temp_folder_name))

            # If the temp folder does not already exist, extract to it
            if not os.path.exists(temp_folder):
                with tarfile.open(tgz_file, "r:gz") as tar:
                    extract_tar(tgz_file, temp_folder)

        # Get only the relevant data files (for the given combination of date and region (AU))
        data_files = [f for f in Path(au_date_folder).rglob("*.txt") if "sockets" not in f.name]

        # Define the path to a folder to be used for calculating the scores (I.e used as results_folder), and create it if it doesn't exist
        final_data = Path(au_date_folder) / "final_data"
        final_data.mkdir(parents=True, exist_ok=True)
        
        # Create a hardlink (I.e an optimised copy) for each data file and put it into final_data
        for file in data_files:
            destination_file_path = os.path.join(final_data, file.name)
            if not os.path.exists(destination_file_path):
                os.link(file, destination_file_path)

        # Get the appropriate sockets_file from the directory containing the sockets data
        for file in os.scandir(socket_data_path):
            if au_date_folder.name in file.name:
                sockets_file = file
                break
        
        # Define the appropriate path to the final_data folder for the calculate_scores() function
        results_folder = au_data_path + "/" + au_date_folder.name + "/" + final_data.name

        # Use calculate_scores() to calculate and write the scores
        calculate_scores(sockets_file, results_folder, scores_file)

        # Remove all the temporary folders
        for file in os.scandir(au_date_folder):
            if file.is_dir() and "thread" in file.name:
                shutil.rmtree(file)

        # Remove the results_folder 
        shutil.rmtree(results_folder)


    # Get all tgz files to be extracted for NZ such as results-nz-20230512.tgz
    tgz_files = list(Path(nz_data_path).rglob("*.tgz"))

    # Iterate through each tgz file, and process/extract it
    for tgz_file in tgz_files:
        
        # Create/define a temporary folder for extraction
        temp_folder_name = tgz_file.name.replace(".tgz", "")
        temp_folder = Path(os.path.join(nz_data_path, temp_folder_name))

        # Define the path to where the scores file should be placed
        scores_file = Path(nz_data_path + "/" + temp_folder.name + "-scores.txt")

        # If the scores file for the given tgz file already exists, simply move on to the next file
        if os.path.exists(scores_file):
            print(str(scores_file) + " already exists")
            continue

        # If the temp folder does not already exist, extract to it
        if not os.path.exists(temp_folder):
            extract_tar(tgz_file, temp_folder)

        # Get only the relevant data files 
        data_files = [f for f in Path(temp_folder).rglob("*.txt") if "sockets" not in f.name]

        # Define the path to a folder to be used for calculating the scores (I.e used as results_folder), and create it if it doesn't exist
        final_data = Path(temp_folder) / "final_data"
        final_data.mkdir(parents=True, exist_ok=True)

        # Create a hardlink (I.e an optimised copy) for each data file and put it into final_data
        for file in data_files:
            destination_file_path = os.path.join(final_data, file.name)
            if not os.path.exists(destination_file_path):
                os.link(file, destination_file_path)

        # Get the appropriate sockets_file from the directory containing the sockets data
        for file in os.scandir(socket_data_path):
            if temp_folder.name.replace("results-", "") in file.name:
                sockets_file = file
                break

        # Define the appropriate path to the final_data folder for the calculate_scores() function
        results_folder = nz_data_path + "/" + temp_folder.name + "/" + final_data.name

        # Use calculate_scores() to calculate and write the scores
        calculate_scores(sockets_file, results_folder, scores_file)

        # Remove all the temporary/extracted folders
        for file in os.scandir(nz_data_path):
            if file.is_dir():
                shutil.rmtree(file)
