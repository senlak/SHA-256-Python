#shell.py

from sha256 import sha256_hash as sh, sha256_find as sf
from tests import *


def run():
    print('SHA-256 Hash Computation Shell (Type \"help\" for commands)\n\n')
    while 1:
        try:
            cmd = input('>>> ').split(' ', maxsplit=1)
            l = len(cmd)
            if (l == 1):
                if (cmd[0] == 'help'):
                    print(
                        '\nhash [input message]  : generates the SHA-256 hash of the given input message string'
                    )
                    print(
                        'hashx [input message] : generates the SHA-256 hash of the given hex'
                    )
                    print(
                        'find [hash]           : tries to find the original input message of the given SHA-256 hash by brute-forcing'
                    )
                    print('tests                 : runs the tests')
                    print('extests               : runs the extended tests')
                    print('exit                  : exits the shell\n')
                elif (cmd[0] == 'tests'):
                    start_time = time()
                    tests(tva)
                    print("--- %s seconds ---" % (time() - start_time))
                elif (cmd[0] == 'extests'):
                    start_time = time()
                    tests(file2tva("tva\SHA256ShortMsg.rsp"))
                    tests(file2tva("tva\SHA256LongMsg.rsp"))
                    print("--- %s seconds ---" % (time() - start_time))
                elif (cmd[0] == 'exit'):
                    exit()
            elif (l == 2):
                if (cmd[0] == 'hash'):
                    start_time = time()
                    print('\nHash : ' + sh(cmd[1]) + '\n')
                    print("--- %s seconds ---" % (time() - start_time))
                elif (cmd[0] == 'hashx'):
                    start_time = time()
                    print('\nHash : ' + sh(bytearray.fromhex(cmd[1])) + '\n')
                    print("--- %s seconds ---" % (time() - start_time))
                elif (cmd[0] == 'find'):
                    print('\nOriginal input message : ' + sf(cmd[1]) + '\n')
        except Exception as e:
            print("Error : ", e.__class__)


if __name__ == "__main__":
    run()