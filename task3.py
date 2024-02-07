#task 3 code
import hashlib

def hash_str(password_str): 
    #create sha512 object
    sha512 = hashlib.sha512() 
    #update object with encoded password_str
    sha512.update(password_str.encode())
    #generate and return hashed string
    return sha512.hexdigest()


def dictionary_crack_salted_hash(dict_vals, password_hash, salt): 
    #loop over every password dictionary value 
    for dict_val in dict_vals: 
        #create string with dict val and salt
        salted_dict_val = dict_val + salt
        #get hash of salted value 
        hashed_val = hash_str(salted_dict_val)
        #check if hash matches password hash 
        if hashed_val == password_hash: 
            #if match is found, return dict val 
            return dict_val
    
    #if no match is found, return default value 
    return "Password Not Found"


def dictionary_crack_salted_hashes(dict_vals, hash_salt_list): 
    result_list = []
    #for every salted hash find the password string
    for hash_salt in hash_salt_list: 
        password_str = dictionary_crack_salted_hash(dict_vals, hash_salt[0], hash_salt[1])
        result_list.append(password_str)

    return result_list


if __name__ == "__main__": 
    #load dictionary values 
    file_name = "PasswordDictionary.txt"
    password_dictionary_list = []
    with open(file_name, "r") as file: 
        #read each line in the file, strip spaces and add password to list 
        for line in file: 
            password_dictionary_list.append(line.strip())

    #list of hashes that we want to crack
    hash_salt_list =  [
        ('63328352350c9bd9611497d97fef965bda1d94ca15cc47d5053e164f4066f546828eee451cb5edd6f2bba1ea0a82278d0aa76c7003c79082d3a31b8c9bc1f58b', 
         'dbc3ab99'),
        ('86ed9024514f1e475378f395556d4d1c2bdb681617157e1d4c7d18fb1b992d0921684263d03dc4506783649ea49bc3c9c7acf020939f1b0daf44adbea6072be6', 
         'fa46510a'),
        ('16ac21a470fb5164b69fc9e4c5482e447f04f67227102107ff778ed76577b560f62a586a159ce826780e7749eadd083876b89de3506a95f51521774fff91497e', 
         '9e8dc114'),
        ('13ef55f6fdfc540bdedcfafb41d9fe5038a6c52736e5b421ea6caf47ba03025e8d4f83573147bc06f769f8aeba0abd0053ca2348ee2924ffa769e393afb7f8b5', 
         'c202aebb'),
        ('9602a9e9531bfb9e386c1565ee733a312bda7fd52b8acd0e51e2a0a13cce0f43551dfb3fe2fc5464d436491a832a23136c48f80b3ea00b7bfb29fedad86fc37a', 
         'd831c568'),
        ('799ed233b218c9073e8aa57f3dad50fbf2156b77436f9dd341615e128bb2cb31f2d4c0f7f8367d7cdeacc7f6e46bd53be9f7773204127e14020854d2a63c6c18', 
         '86d01e25'),
        ('7586ee7271f8ac620af8c00b60f2f4175529ce355d8f51b270128e8ad868b78af852a50174218a03135b5fc319c20fcdc38aa96cd10c6e974f909433c3e559aa', 
         'a3582e40'),
        ('8522d4954fae2a9ad9155025ebc6f2ccd97e540942379fd8f291f1a022e5fa683acd19cb8cde9bd891763a2837a4ceffc5e89d1a99b5c45ea458a60cb7510a73', 
         '6f966981'),
        ('6f5ad32136a430850add25317336847005e72a7cfe4e90ce9d86b89d87196ff6566322d11c13675906883c8072a66ebe87226e2bc834ea523adbbc88d2463ab3', 
         '894c88a4'),
        ('21a60bdd58abc97b1c3084ea8c89aeaef97d682c543ff6edd540040af20b5db228fbce66fac962bdb2b2492f40dd977a944f1c25bc8243a4061dfeeb02ab721e', 
         '4c8f1a45')
        ]
    #get list of passwords
    password_list = dictionary_crack_salted_hashes(password_dictionary_list, hash_salt_list)
    #print each password in the terminal
    for password in password_list: 
        print(password)