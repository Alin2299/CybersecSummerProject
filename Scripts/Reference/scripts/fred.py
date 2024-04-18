import pandas as pd

# Data for matrix
data = {'A': [45,37,42,35,39,22,17,46,87,23],
        'B': [38,31,26,28,33,22,17,46,87,23],
        'C': [10,15,17,21,12,34,81,32,45,19]
        }

df = pd.DataFrame(data,columns=['A','B','C'])
print("Original dataframe")
print(df) # original df
print("\n")

corrMatrix = df.corrwith(df["B"]) # finding correlations
print("Between column B and the rest of the dataframe")
print("Correlation Coefficients Matrix")
print(corrMatrix) # printing correlations
print('\n')

corrMatrix = df.corrwith(df["C"]) # finding correlations
print("Between column C and the rest of the dataframe")
print("Correlation Coefficients Matrix")
print(corrMatrix) # printing correlations
print('\n')

corrMatrix = df.corrwith(df["C"]) # finding correlations
print("Between column C and the rest of the dataframe")
print("Correlation Coefficients Matrix")
print(corrMatrix) # printing correlations
