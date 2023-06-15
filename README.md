# Client Server Protocol using Python Socket With AES and SSL

## Usage
1. Install required library using following command
    ```
    pip install pycryptodome
    pip install pyjwt[crypto]
    ```
    
2. Run below code in terminal to start server
    ```
    python server.py
    ```
    Once you start server you have to insert SSL PEM Password. 

    Password = **test123**

3. Run below command in another terminal
    ```
    python client.py
    ```
    Once you run the above command it will ask for username and password.
    
    Username = **test**

    Password = **test**

## Known errors:
    ModuleNotFoundError: No module named 'Crypto'

#### Even after installng **pycryptodome** library If you got the above error, Please run below commands in your terminal

### **Solution:**
    pip uninstall crypto 
    pip uninstall pycrypto 
    pip install pycryptodome
    

## Libraries used:
1. **socket**: used for client server communication
2. **json**: used to convert received data from string to json
3. **random**: used to generate random string for key
4. **string**: used to get lowercase letters
5. **hashlib**: 
6. **ssl**: used to wrap socket(For mutual authencation) 
7. **uuid**: used to get mac address of system(For client)
8. **sys**: used to exit code
9. **os**: used to get file name
10. **jwt**: Used to generate jwt token from username and password
11. **AES**: Used to encrypt/ decrypr data passes in DATA_RESPONSE

## How code works(Flow):
1. Client Send HELLO message with username, password and MAC address

2. Server match username and password.
    - If username and password match then  generate token from username and password, store mac address, client IP address in sessions and generate unique sessionId and send HELLO_ACK(acknowledge) message along with sessionId, token, encryption key and Initial Vector(Encryption Key and Initial vector is used for AES Encryption/Decryption.).
    - if username and/or password does not match then send close message with isAuthencation=false, and close connection

3. Once handshaking is done, Client store token, Encryption key, initial vector and session id.

4. Client increment sequence number and send DATA_REQUEST message along with token, sequence number, sessionId **every 30 seconds**. Token is passed in header so that server can verify the user.

5. Server verify token and sessionId in each request. 
    - If one of them is wrong then server shutdown the connection. From sessionId server match client IP address store in sessions with the socket connection ip address.
    - If token and sessionId verified then server send DATA_RESPONSE message contains a data field containing a encrypted string, current sessionId and sequence number.
    - Steps to encrypt data field
        1. Generate random string using following function:
        ```
        def get_random_string(length):
            # choose from all lowercase letter
            letters = string.ascii_lowercase
            result_str = ''.join(random.choice(letters) for i in range(length))
            return result_str
        
        string = get_random_string(8)
        ```
        2. Encrypt generated random string using AES encryprion algorithm
        ```
        encrypted = obj_enc.encrypt(string.encode('utf-8'))
        ```
        3. AES encryption generate byte output, so convert it to integer using following code:
        ```
         byteToInt = int.from_bytes(encrypted, "big")
        ```
        4. Add 1269 in the generate integer number using following function to mislead hacker(additional encryption)
        ```
        def patternToEncrypt(val):
            return (val + 1269)
        
        data = patternToEncrypt(byteToInt)
        ```

6. After getting DATA_RESPONSE from server client decrypt data field.
    - Steps to decrypt data field:
        1. substract 1269 from received data using following function:
        ```
            def patternToDecrypt(val):
                return int(val - 1269)
            
            data = patternToDecrypt(dataResponse['data']['data'])
        ```
        2. convert integer to byte
        ```
        def convertIntToByte(data):
            return data.to_bytes((data.bit_length() + 7) // 8, 'big')

        byteData = convertIntToByte(data) # This is just an example how we can pass value
        ```
        3. decrypt byte using AES
        ```
        decrypted = obj_dec.decrypt(convertIntToByte(dataResponse['data']['data']))

        ```

6. Server regenerate Encryption key at every 10 DATA_RESPONSE messages.

7. The Client terminates the connection after 30 minutes. When closing the session, the Client send CLOSE message to the Server.

## Example of Request/Response

1. Client Send Hello Message:
    ```
    Sending: {
        "header": {
            "MAC": "f8:94:c2:02:86:ee"
        },
        "data": {
            "username": "test",       
            "password": "test",
            "message-type": "HELLO",
            "sequence": 1
        }
    }
    ```
2. Server send close message if authencation failed
    ```
    Sending: {
        "header": {},
        "data": {
            "sequesce": 1,
            "isAuthencatedUser": "false",
            "message-type": "CLOSE"
        }
    }
    ```

2. Server Authencate user and send acknowledge message:
    ```
    Received: {      
        "header": {},
        "data": {
            "sequesce": 1,
            "sessionId": 1,
            "message-type": "HELLO_ACK",
            "isAuthencatedUser": "True",
            "key1": 56143797824841494679021642319300020262282527220539511750690840295639543043255,        
            "key2": 156046093517905918062671563777744272733,
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiY2xpZW50MSIsImlkIjoxfQ.-KZFtKz9CTWwtGPdsxVHHekeNxDLyeiPr3d1QHIxoXk"
        }
    }
    ```

3. Client send DATA_REQUEST 
    ```
    Sending:{
        "header": {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiY2xpZW50MSIsImlkIjoxfQ.-KZFtKz9CTWwtGPdsxVHHekeNxDLyeiPr3d1QHIxoXk"
        },
        "data": {
            "sessionId": 1,
            "message-type": "DATA_REQUEST",
            "sequence": 2
        }
    }
    ```
4. Server Send DATA_RESPONSE
    ```
    {
        "header": {},
        "data": {
            "sequesce": 2,
            "sessionId": 1,
            "message-type": "DATA_RESPONSE",
            "data": 12621679940747315704
        }
    }
    ```
5. Client Send CLOSE Message before timeout
    ```
    {
        "header": {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiY2xpZW50MSIsImlkIjoxfQ.-KZFtKz9CTWwtGPdsxVHHekeNxDLyeiPr3d1QHIxoXk"
        },
        "data": {
            "sessionId": 1,
            "message-type": "CLOSE",
            "sequence": 11,
            "isConnectionClose": "True"
        }
    }
    ```

### Exceptions:
1. If IP address not matched with the ip address stored in session:
    ```
    Exception: Client IP address does not match with the IP address stored in session. file: server.py line: 149
    Sending: {
        "header": {},
        "data": {
            "sequesce": 2,
            "message-type": "CLOSE"
        }
    }
    ```
2. If session id is different:
    ```
    Exception: Session Id does not match
    Sending: {
        "header": {},
        "data": {
            "sequesce": 2,
            "isAuthencatedUser": "false",
            "message-type": "CLOSE"
        }
    }
    ```