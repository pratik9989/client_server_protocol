import socket
import json
import time
import datetime
from threading import Timer
import sys
import hashlib
from Crypto.Cipher import AES
import ssl
import uuid, re

def getMac():
    return ':'.join(re.findall('..', '%012x' % uuid.getnode()))

def encryption(KEY, IV):
    # creating an object to encrypt our data with
    return AES.new(KEY, AES.MODE_CFB, IV)

# additional layer for decryption
def patternToDecrypt(val):
    return int(val - 1269)

def convertIntToByte(data):
    return data.to_bytes((data.bit_length() + 7) // 8, 'big')
    
def decodeData(client_socket):
    data = client_socket.recv(1024)  # receive response
    data = data.decode("utf-8")
    json_acceptable_string = data.replace("'", "\"")
    d = json.loads(json_acceptable_string)
    return d

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number
    token = ''
    messages = []
    dataToSend = {
        "header":{},
        "data":{}
    }
    # initial messgae sequence
    sequence = 0
    # Current session ID
    sessionId = None

    
    c_socket = socket.socket()  # instantiate
    # provide full path to the certificate file location
    client_socket = ssl.wrap_socket(
        sock=c_socket, cert_reqs=ssl.CERT_REQUIRED, ca_certs='cert.crt', do_handshake_on_connect=True)
    # the above function "wraps" the socket created with the security layer of signed certificate

    client_socket.connect((host, port))  # connect to the server

    duration = 0.5  # Duration is in minute.
    timeoutTime = time.time() + 60*duration

    # first time client enter message, username and password send hello message(Hand shaking)
    uname = input(" Username -> ")  # take Username
    dataToSend['data']['username'] = uname
    password = input(" Password -> ")  # take Password
    dataToSend['data']['password'] = password

    # message = input(" -> ")  # take input
    dataToSend['data']['message-type'] = "HELLO"
    # increment sequence on new message
    sequence = sequence + 1
    dataToSend['data']['sequence'] = sequence
    dataToSend['header']['MAC'] = getMac()
    print('\n')
    print('Sending:', dataToSend['data'])

    # Send data to server
    client_socket.write(
        bytes(str(dataToSend), encoding="utf-8"))  # send message
    # empty dataToSend after sending message
    dataToSend = {
        "header":{},
        "data":{}
    }
    response = decodeData(client_socket)
    print('Received:', response)
    print('\n')

    # if authencation failed and server send close message then close connection
    if (response['data']['message-type'] == 'CLOSE'):
        print('Authencation failes, server sent close message')
        client_socket.close()  # close the connection
    elif (('isAuthencatedUser' in response['data']) and (response['data']['isAuthencatedUser'] == 'True') and ('key1' in response['data'])):
        try:
            # Handshaking done, user is authencated and server send cipher key
            token = response['data']['token']
            key1 = convertIntToByte(patternToDecrypt(response['data']['key1']))
            key2 = convertIntToByte(patternToDecrypt(response['data']['key2']))
            sessionId = response['data']['sessionId']
            # encryption algorithm
            obj_dec = encryption(key1, key2)
            # after setting key in local variable we don't need to send key again and again
            # response['data'].pop('key1')
            # response['data'].pop('key2')

            while True:
                # send token everytime in header, So that server can verify client
                dataToSend['header']['token'] = token
                dataToSend['data']['sessionId'] = sessionId
                # check if duration exceed
                if (time.time() >= timeoutTime):
                    print(f"Timeout: it's been {duration} minute, So close connection")
                    # before closing connection send close message to client
                    dataToSend['data']['message-type'] = 'CLOSE'  # Client request for data
                    # increment sequence to maintain order
                    sequence = sequence + 1
                    dataToSend['data']['sequence'] = sequence
                    # dataToSend['data']['sequence'] = str(int(dataToSend['data']['sequence']) + 1)
                    dataToSend['data']['isConnectionClose'] = 'True'
                    print('Sending:', dataToSend['data'])
                    client_socket.write(
                        bytes(str(dataToSend), encoding="utf-8"))  # send message
                    # client_socket.close()
                    break

                dataToSend['data']['message-type'] = 'DATA_REQUEST'  # Client request for data

                # increment sequence to maintain order
                sequence = sequence + 1
                dataToSend['data']['sequence'] = sequence
                # dataToSend['data']['sequence'] = str(int(dataToSend['data']['sequence']) + 1)
                print('Sending:', dataToSend['data'])
                client_socket.write(bytes(str(dataToSend), encoding="utf-8"))  # send message
                # empty dataToSend after sending message
                dataToSend = {
                            "header":{},
                            "data":{}
                        }
                # get response
                dataResponse = decodeData(client_socket)

                # close connection if server send close message
                if (dataResponse['data']['message-type'] == 'CLOSE'):
                    print('Authencation failes, server sent close message')
                    client_socket.close()  # close the connection
                    break

                print('Received:', dataResponse['data'])
                
                if('key1' in dataResponse['data']):
                    print('Key refreshed from server')
                    key1 = convertIntToByte(patternToDecrypt(dataResponse['data']['key1']))
                    # encryption algorithm
                    obj_dec = encryption(key1, key2)
                
                decrypted = obj_dec.decrypt(convertIntToByte(dataResponse['data']['data']))
                print(f"Decrypted data received in DATA_RESPONSE: {decrypted.decode('utf-8')}")
                print('\n')
                # sleep for 30 second
                time.sleep(3)
        except Exception as e:
            if(type(e).__name__ == "KeyError"):
                print('*******************Error***************************')
                print(f'Error: Key {str(e)} not found in response')
            else:
                print('Exception', str(e))
    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()