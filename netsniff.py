def parseInput(data):
    # Parse the input and returns the ip address
    parsed_data = data.split(".")
    if len(parsed_data) != 4:
        raise ValueError("Invalid IP Address")
    for octet in parsed_data:
        if not octet.isdigit() or int(octet) < 0 or int(octet) > 255:
            raise ValueError("Invalid IP Address")
    return data


print("Enter Target IP Address: ")
ip = parseInput(input())
print("Entered IP Address:", ip)
