with open('/dev/module_keyboard', 'r') as f:
    while True:
        data = f.readline()
        if data:
            print(data.strip())
