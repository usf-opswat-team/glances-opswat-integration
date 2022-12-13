import hashlib
import os.path
def check_file(filepath:str):
# file to check
    if not os.path.isfile(filepath):
        return "X"  
def mdc_hash(filepath: str) -> str:
        """Hash a file located at filepath"""
        result = hashlib.sha256()
        file_from_path = open(filepath, 'rb')
        with file_from_path as file:
            read_file = file.read(1024)
            while len(read_file) > 0:
                result.update(read_file)
                read_file = file.read(1024)
        hash = result.hexdigest()
        file_from_path.close()
        return hash
print(check_file("./test.txt"))       
#print(check_file("./test.txt"))
