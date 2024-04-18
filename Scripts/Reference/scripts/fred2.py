import pandas as pd

# Data for matrix
data1 = [45,37,42,35,39,22,17,46,87,23]
data2 = [38,31,26,28,33,22,17,46,87,23]
data3 = [1,1,1,1,1,1,0,0,0,0]
data4 = [1,1,1,0,0,0,0,0,1,1]

df1 = pd.DataFrame(data1)
df2 = pd.DataFrame(data2)
df3 = pd.DataFrame(data3)
df4 = pd.DataFrame(data4)
print("Original dataframe 1")
print(df1) # original df
print("\n")

corrMatrix = df1.corrwith(df2) # finding correlations
print("Between column B and the rest of the dataframe")
print("Correlation Coefficients Matrix")
print(corrMatrix) # printing correlations
print('\n')

corrMatrix = df2.corrwith(df3) # finding correlations
print("Between column C and the rest of the dataframe")
print("Correlation Coefficients Matrix")
print(corrMatrix) # printing correlations
print('\n')

corrMatrix = df3.corrwith(df2) # finding correlations
print("Between column C and the rest of the dataframe")
print("Correlation Coefficients Matrix")
print(corrMatrix) # printing correlations

corrMatrix = df4.corrwith(df3) # finding correlations
print("Between column D and the rest of the dataframe")
print("Correlation Coefficients Matrix")
print(corrMatrix) # printing correlations
