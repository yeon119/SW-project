import datetime

now = datetime.datetime.now()

print(now.year)  #2023
print(now.month)  #10
print(now.day)  # 4

print(now.hour)
print(now.minute)
print(now.second)

if now.hour < 12:
  print("오전")
else:
  print("오후")

