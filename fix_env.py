import os

def clean_env_file():
    env_path = '.env'
    if not os.path.exists(env_path):
        print(f"{env_path} does not exist.")
        return

    try:
        # Read as binary to handle weird encodings/nulls
        with open(env_path, 'rb') as f:
            content = f.read()
        
        # Decode ignoring errors to filter out bad bytes, then remove nulls
        text = content.decode('utf-8', errors='ignore').replace('\x00', '').replace('\r\r', '\r')
        
        lines = text.splitlines()
        clean_lines = []
        
        receiver_set = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check if this line defines RECEIVER_EMAIL
            if line.startswith('RECEIVER_EMAIL='):
                clean_lines.append("RECEIVER_EMAIL=2211cs010440@mallareddyuniversity.ac.in")
                receiver_set = True
            else:
                clean_lines.append(line)
        
        # If receiver wasn't found, add it
        if not receiver_set:
            clean_lines.append("RECEIVER_EMAIL=2211cs010440@mallareddyuniversity.ac.in")

        # Write back cleanly
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(clean_lines) + '\n')
            
        print("Successfully cleaned .env file and set RECEIVER_EMAIL.")
        
        # Check values
        with open(env_path, 'r', encoding='utf-8') as f:
            print("\nCurrent .env content (masked):")
            for l in f:
                if 'PASSWORD' in l:
                    print(l.split('=')[0] + '=********')
                else:
                    print(l.strip())

    except Exception as e:
        print(f"Error cleaning .env: {e}")

if __name__ == "__main__":
    clean_env_file()
