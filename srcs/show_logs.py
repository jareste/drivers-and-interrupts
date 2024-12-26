with open('/dev/jareste_keylogger', 'r') as f:
    while True:
        data = f.readline()
        if data:
            print(data.strip())
