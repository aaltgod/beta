import requests
import random
import string
import urllib.parse


url = 'http://test-beta:5000/echo'

def generate_flag(length=32):
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=length - 1))
    return random_str + '='

def send_json(url, flag:str):
    response = requests.post(url, headers={'Content-Type': 'application/json'}, json={"data": flag})
    print("RESP", response.text)

    received_flag = response.json().get('data')
    return received_flag

def send_form(url, flag: str):
    response = requests.post(url, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data={"data": flag})
    print("RESP", response.text)

    parsed_response = urllib.parse.parse_qs(response.text)
    received_flag = parsed_response.get('data', [None])[0]
    return received_flag

def test_flag_in_json():
    expected_flag = generate_flag()
    received_flag = send_json(url, expected_flag)

    assert received_flag == expected_flag, f"Expected flag is {expected_flag}, received flag is {received_flag}"

def test_flag_in_form():
    expected_flag = generate_flag()
    received_flag = send_form(url, expected_flag)

    assert received_flag == expected_flag, f"Expected flag is {expected_flag}, received flag is {received_flag}"