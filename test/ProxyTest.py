import requests

def upload_file (filename, data, embed = False, timestamp = 0):
	if embed:
		filename = filename + "?embed&timestamp=" + str (timestamp)
	r = requests.post ("http://localhost:9000/upload/" + str (filename), data = data)
	return r

def delete_file (filename):
	r = requests.get ("http://localhost:9000/delete/" + str (filename))
	return r

def get_file (filename, embed = False):
	if embed:
		filename = filename + "?embed"
	r = requests.get ("http://localhost:80/get/" + str (filename))
	return r

def prepare_file (filename, data, size):
	r = requests.post ("http://localhost:9000/upload/" + str (filename) + "?prepare=" + str (size), data = data)
	return r

def plain_write_file (filename, data, offset):
	r = requests.post ("http://localhost:9000/upload/" + str (filename) + "?plain_write&offset=" + str (offset), data = data)
	return r

def commit_file (filename, data, offset):
	r = requests.post ("http://localhost:9000/upload/" + str (filename) + "?commit&offset=" + str (offset), data = data)
	return r

def request_successful (r):
	if r.status_code != 200:
		raise Exception ("Request failed. Status code: " + str (r.status_code))

def verify_data (filename, data, embed = False):
	r = get_file (filename, embed)
	request_successful (r)
	if r.content != data:
		raise Exception ("Wrong content: " + str (r.content) + ". Expected content: " + str (data))

def test1 ():
	embed = True
	filename = "file1.txt"
	data = "Test data"
	print "*INFO* Upload"
	r = upload_file (filename, data, embed = embed, timestamp = 3)
	request_successful (r)
	print "*INFO* Verify"
	verify_data (filename, data, embed)
	print "*INFO* Delete"
	r = delete_file (filename)
	request_successful (r)

def test2 ():
	filename = "file1.txt"
	data = "Test data"
	print "*INFO* Prepare"
	#r = prepare_file (filename, data [:2], len (data))
	r = prepare_file (filename, "Te", 9)
	request_successful (r)
	print "*INFO* Plainr write"
	#r = plain_write_file (filename, data [2:6], 2)
	r = plain_write_file (filename, "st d", 2)
	request_successful (r)
	print "*INFO* Commit"
	#r = commit_file (filename, data [6:], 6)
	r = commit_file (filename, "ata", 6)
	request_successful (r)
	print "*INFO* Verify"
	verify_data (filename, data)
	print "*INFO* Delete"
	r = delete_file (filename)
	request_successful (r)

if __name__ == "__main__":
	test1 ()
	test2 ()
