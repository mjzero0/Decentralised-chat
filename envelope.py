import json 
import uuid
import time


#this Envelope format follows SOCP outline 
def make_envelope(msg_type, sender, receiver, payload):
     return {
        "type": msg_type,
        "from": sender,
        "to": receiver,
        "ts": int(time.time() * 1000),  # timestamp in ms
        "payload": payload,
        "sig": ""  # this is for crypto, will do later
    }

# this function is for turning the above dictionary format into a json file
#json.dumps does that
def to_json(envelope):

    return json.dumps(envelope) + "\n"



# just to test
if __name__ == "__main__":
    sender = str(uuid.uuid4())
    receiver = str(uuid.uuid4())
    env = make_envelope("PING", sender, receiver, {"msg": "hello world"})
    print(to_json(env))