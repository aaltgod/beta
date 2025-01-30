import requests
import random
import string
import urllib.parse
import pytest


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

# flags_quantity=1 - default case
# flags_quantity=2 - test for processing of multiple flags
# flags_quantity=20 - triggers server-side encoding by sending a large payload, this is for encoding/decoding testing of `beta`
@pytest.mark.parametrize("flags_quantity,repeats", [(1, 1), (2, 100), (20, 1000)])
def test_flag_in_json(flags_quantity, repeats):
    for _ in range(repeats):
        expected_flag = ''.join([generate_flag() for _ in range(flags_quantity)])
        received_flag = send_json(url, expected_flag)

        assert received_flag == expected_flag, f"Expected flag is {expected_flag}, received flag is {received_flag}"

# flags_quantity=1 - default case
# flags_quantity=2 - test for processing of multiple flags
# flags_quantity=20 - triggers server-side encoding by sending a large payload, this is for encoding/decoding testing of `beta`
@pytest.mark.parametrize("flags_quantity,repeats", [(1, 1), (2, 1), (20, 1)])
def test_flag_in_form(flags_quantity, repeats):
    for _ in range(repeats):
        expected_flag = ''.join([generate_flag() for _ in range(flags_quantity)])
        received_flag = send_form(url, expected_flag)

        assert received_flag == expected_flag, f"Expected flag is {expected_flag}, received flag is {received_flag}"