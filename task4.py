#task 4 code
import hashlib 
import hmac 
import math 

#libraries used for generating performance plot
import timeit
import pandas as pd
import matplotlib.pyplot as plt
import os
#reusing the hash_str function implemented in task 3
from task3 import hash_str

#generate the hmac bytes
def HMAC(password, message): 
    #calculate hmac value from password using SHA512 as the digest mode
    hmac_val = hmac.new(password, message, hashlib.sha512).digest() 
    return hmac_val


def PBKDF2(password, salt, iterations, mk_len):
    #password: password of any length (string)
    #salt: randomly generated salt (string)
    #iterrations: number of itterations that should be performed, 
    #  recommended bigger than (find value with sourece, use 1000 for test)
    #mk_len: the length of the master key (desired key) in bytes

    #get sha512 digest size in bytes
    sha512_digest_len = hashlib.sha512().digest_size

    #check if provided mk_len is not to large (can be at most (2**32 -1)*sha512_digest_len bits)
    if (mk_len > (2**32 -1)*sha512_digest_len): 
        raise ValueError("mk_len is too large")

    #convert password and salt to byte strings
    byte_password = password.encode()
    byte_salt = salt.encode() 

    #calculate how many blocks need to be concattinated to create key of specified size
    num_blocks = math.ceil(mk_len/sha512_digest_len)

    #initialize the master key
    byte_master_key = b""

    #generate blocks 
    for i in range(1, num_blocks + 1):
        #initialize Ti = 0 as a byte string of length 64
        Ti_int = 0 
        Ti = Ti_int.to_bytes(64, "big")

        #initialize U (u0) as the salt concattinated with i, where i is a 32bit integer 
        # in byte format
        byte_i = i.to_bytes(4, "big")
        U = byte_salt + byte_i

        #iterate the specified number of times
        for j in range(1, iterations + 1): 
            #for each iteration, the HMAC message is the previous HMAC digest, the 
            # password is always the same 
            U = HMAC(byte_password, U)

            #bitwise exclusive or (XOR) Ti = Ti XOR Uj
            #bytes are immutable in python so zip is needed to 
            # perform the XOR operation 
            Ti = bytes(Tik ^ Uk for Tik, Uk in zip(Ti, U))
       
        #concatinate Ti to master key to build up the key 
        byte_master_key = byte_master_key + Ti
    
    #adjust the size of the master key to mk_len
    byte_master_key = byte_master_key[:mk_len]
    
    #convert to hex 
    hex_naster_key = byte_master_key.hex()

    #return byte master key 
    return hex_naster_key



def profile_performance(filename): 
    #fixed values 
    password = "test_password"
    salt = "test_salt"
    salted_password = password + salt
    mk_len = 64 #64 bytes = 128 hex = 512bit, same as sha512 

    #varying the number of hashes that should be computed
    number_of_hashes_list = [i for i in range(100, 2001, 100)]

    #arrays for storing result 
    sha512_times = []
    PBKDF2_1000_times = []
    PBKDF2_2000_times = []
    PBKDF2_3000_times = []
    PBKDF2_4000_times = []

    #generate data for different number of hashes
    for number_of_hashes in number_of_hashes_list: 
        print(f"Number of hashes: {number_of_hashes}")
        
        #time the sha512 algorithm 
        sha512_time = timeit.timeit(lambda:hash_str(salted_password), 
                                    number=number_of_hashes*4000)
        sha512_times.append(round(sha512_time, 10))
        
        #time PBKDF2 alroithm with 1000 iterations
        PBKDF2_time = timeit.timeit(lambda:PBKDF2(password, salt, 1000, mk_len), 
                                    number=number_of_hashes)
        PBKDF2_1000_times.append(round(PBKDF2_time, 10))

        #time PBKDF2 alroithm with 2000 iterations
        PBKDF2_time = timeit.timeit(lambda:PBKDF2(password, salt, 2000, mk_len), 
                                    number=number_of_hashes)
        PBKDF2_2000_times.append(round(PBKDF2_time, 10))

        #time PBKDF2 alroithm with 3000 iterations
        PBKDF2_time = timeit.timeit(lambda:PBKDF2(password, salt, 3000, mk_len), 
                                    number=number_of_hashes)
        PBKDF2_3000_times.append(round(PBKDF2_time, 10))

        #time PBKDF2 alroithm with 4000 iterations
        PBKDF2_time = timeit.timeit(lambda:PBKDF2(password, salt, 4000, mk_len), 
                                    number=number_of_hashes)
        PBKDF2_4000_times.append(round(PBKDF2_time, 10))

    #combine data to a panda dataframe 
    performance_data_dict = {
        "Number of hashes": number_of_hashes_list,
        "SHA512 time (s) (scaled by a factor of 4000)": sha512_times, 
        "PBKDF2 1000 iterations time (s)": PBKDF2_1000_times,
        "PBKDF2 2000 iterations time (s)": PBKDF2_2000_times, 
        "PBKDF2 3000 iterations time (s)": PBKDF2_3000_times, 
        "PBKDF2 4000 iterations time (s)": PBKDF2_4000_times,  
    }
    df_performance_data = pd.DataFrame(performance_data_dict)

    #save data as a CSV 
    df_performance_data.to_csv(filename)


def plot_performance_data(filename): 
    #load the performance data
    df_performance_data = pd.read_csv(filename, index_col=0)

    #set the figure size
    plt.figure(figsize=(10, 6))

    #dictionary for mapping the column name to legend label 
    legend_dict = {
        "SHA512 time (s) (scaled by a factor of 4000)": "SHA512 (scaled by a factor of 4000)",
        "PBKDF2 1000 iterations time (s)": "PBKDF2 1000 iterations", 
        "PBKDF2 2000 iterations time (s)": "PBKDF2 2000 iterations", 
        "PBKDF2 3000 iterations time (s)": "PBKDF2 3000 iterations", 
        "PBKDF2 4000 iterations time (s)": "PBKDF2 4000 iterations",
    }

    #plot each column of the dataframe 
    x = df_performance_data["Number of hashes"]
    columns_to_plot = [column for column in df_performance_data.columns if column != "Number of hashes"]
    for column in columns_to_plot: 
        plt.plot(x, df_performance_data[column], label=legend_dict.get(column))
    
    #label the plot
    plt.title("SHA512 vs PBKDF2 Performance") 
    plt.xlabel("Number of hashes")
    plt.ylabel("Time (s)") 
    plt.legend() 
    plt.tight_layout()
    #save plot as png
    plt.savefig("algorithm_performance_plot.png")
    #show the plot
    plt.show()





if __name__ == "__main__": 
    #testing PBKDF2 implementation 
    password = "password123"
    salt = "salt" 
    iterations = 1000
    mk_len = 64 #64 bytes = 128 hexadecimal digest = 4*128 = 512 bits same as sha512

    #expected output 
    test_result = "0ecb3c32f57685303ff0878481d223bc1a16eb13bd46cf03d275e0ed43e52104b4ca156b01abb36ee95149c8bbbbb611b88634ffe235bd531e2a087a84d7fc85"
    
    #generate the master key
    master_key = PBKDF2(password, salt, iterations, mk_len)
    print(f"Generated master key: {master_key}")
    print(f"length of generated master key (bytes): {len(master_key)}")

    #check if the generated and expected key match 
    if master_key == test_result: 
        print("Generated master key is the same as the expected master key")

   
    ## generate performance plot
    #check if the performance data has already been generated
    filename = "algorithm_performance_data.csv"
    if not os.path.isfile(filename):
        #if the file does not exist, generate perfromance data
        profile_performance(filename)
    #plot performance data stored in the csv file
    plot_performance_data(filename)