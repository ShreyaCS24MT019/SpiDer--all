import time

# Current timestamp
now = time.time()
print(f"Timestamp: {now}")

# Convert to readable
readable = time.ctime(now)
print(f"Readable: {readable}")
