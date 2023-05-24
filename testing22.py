import hashlib
import binascii
import ecdsa
import random
import multiprocessing
from Crypto.Hash import RIPEMD160


def pubkey_to_hash160(public_key_bytes):
    sha256 = hashlib.sha256(public_key_bytes).digest()
    hash160 = RIPEMD160.new(sha256)
    return hash160.hexdigest()

def find_private_key(input_tuple, results_queue):
    start_number, end_number, target_hashes, subrange_size = input_tuple
    curve = ecdsa.SECP256k1

    for subrange_start in range(start_number, end_number + 1, subrange_size):
        subrange_end = min(subrange_start + subrange_size - 1, end_number)
        print(f"Scanning subrange: {subrange_start} - {subrange_end}")

        private_key_range = list(range(subrange_start, subrange_end + 1))
        random.shuffle(private_key_range)

        for number in private_key_range:
            private_key = ecdsa.SigningKey.from_secret_exponent(number, curve)
            public_key = private_key.get_verifying_key().to_string("compressed")
            current_hash160 = pubkey_to_hash160(public_key)

            if current_hash160 in target_hashes:
                results_queue.put((number, current_hash160))

    results_queue.put(None)

def parallel_private_key_search(start_number, end_number, target_hashes, num_cores, subrange_size):
    range_size = (end_number - start_number + 1) // num_cores
    input_tuples = [(start_number + i * range_size, start_number + (i + 1) * range_size - 1, target_hashes, subrange_size) for i in range(num_cores)]

    results_queue = multiprocessing.Queue()
    processes = [multiprocessing.Process(target=find_private_key, args=(input_tuple, results_queue)) for input_tuple in input_tuples]

    for process in processes:
        process.start()

    found_keys = []
    finished_processes = 0
    while finished_processes < len(processes):
        result = results_queue.get()
        if result is None:
            finished_processes += 1
        else:
            found_private_key, found_hash160 = result
            found_keys.append((found_hash160, found_private_key))
            print(f"Private key found for {found_hash160}: {found_private_key}")
            print(f"Private key found (hex): {hex(found_private_key)[2:]}")

    for process in processes:
        process.join()

    return found_keys

def read_hashes_from_file(filename):
    with open(filename, "r") as file:
        return {line.strip() for line in file}

def write_found_keys_to_file(filename, found_keys):
    with open(filename, "w") as file:
        for found_hash160, found_private_key in found_keys:
            file.write(f"{found_hash160}: {found_private_key}\n")

if __name__ == "__main__":
    start_number = 1
    end_number = 100000 - 1
    target_hashes_filename = "hashes.txt"
    target_hashes = read_hashes_from_file(target_hashes_filename)
    num_cores = 52  # Set the number of CPU cores you want to use.
    subrange_size = 400000  # Set the size of each subrange based on your memory requirements.

    found_keys = parallel_private_key_search(start_number, end_number, target_hashes, num_cores, subrange_size)

    if found_keys:
        write_found_keys_to_file("found.txt", found_keys)
        print("Found private keys written to 'found.txt'.")
    else:
        print("No private keys found in the specified range.")
