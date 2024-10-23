from smb.SMBConnection import SMBConnection
from ftplib import FTP, error_perm

class protocol:


    def __init__(self,target) -> None:
        self.target = target


    def check_login_required(self,port=139):
        # Attempt to connect to the Samba server without credentials
        conn = SMBConnection('', '', '', '')

        try:
            # Attempt to connect to the server
            conn.connect(self.target, port)  # Use port 139 for SMB over TCP
            
            # Try to list the shares
            shares = conn.listShares()
            
            if shares:
                return False  # Login not required
            else:
                return True  # Might require login

        except Exception as e:
            return e

        finally:
            conn.close()



    def check_ftp_anonymous_login(self,port=21):
        
        try:
            # Connect to the FTP server
            ftp = FTP()
            ftp.connect(self.target,port)
            # Attempt to login anonymously
            ftp.login()
            files = ftp.nlst()  # List files
            ftp.quit()  # Close the connection
            yield files

        except:
            return False



    





