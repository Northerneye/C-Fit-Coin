import hashlib
import json
import time
from urllib.parse import urlparse
from uuid import uuid4
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
import requests
from flask import Flask, jsonify, request, render_template
import threading
import ast

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = []
        try:
            privatekey = open("priv.key", "r")
            self.private_key = privatekey.read().encode('ISO-8859-1')
            privatekey.close()

            publickey = open("pub.key", "r")
            self.public_key = publickey.read().encode('ISO-8859-1')
            publickey.close()
        except:
            key = RSA.generate(1024)
            self.private_key = key.export_key()
            self.public_key = key.publickey().export_key()
            privatekey = open("priv.key", 'wb')
            privatekey.write(self.private_key)
            privatekey.close()

            publickey = open("pub.key", 'wb')
            publickey.write(self.public_key)
            publickey.close()
        # Create the genesis block
        block = {
            'index': len(self.chain) + 1,
            'timestamp': 0,
            'transactions': [],
            'proof': 100,
            'previous_hash': '1',
            'solved_by': ""
        }
        self.current_transactions = []
        self.chain.append(block)
        block = {
            'index': len(self.chain) + 1,
            'timestamp': 0,
            'transactions': [],
            'proof': 2675,
            'previous_hash': self.hash(self.chain[-1]),
            'solved_by': ""
        }
        self.current_transactions = []
        self.chain.append(block)
        #self.new_block(previous_hash=self.hash(self.chain[0]), proof=100)
        try:
            savedChain = open("blockchain.save", "r")
            self.chain = ast.literal_eval(savedChain.read())
            savedChain.close()
            print("previous blockchain loaded")
        except:
            print("chain not loaded")

    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.append(parsed_url.netloc)
            return True
        elif parsed_url.path:
            self.nodes.append(parsed_url.path)
            return True
        else:
            raise ValueError('Invalid URL')
        return False

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False
            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], block['previous_hash']):
                return False
            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):

        neighbours = self.nodes
        new_chain = None
        mined = 0

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if (chain[0] != self.chain[0]):
                    return False
                if length > max_length and self.valid_chain(chain):
                    transactionnumb = 0
                    transactionnum = 0
                    nicknames = []
                    for j in range(length):
                        nicknamecheck = 0
                        for transaction in chain[j]['transactions']:
                            if (transaction['amount'] == ""):
                                return False
                            if (int(transaction['amount']) < 0):
                                return False
                            if (transaction['sender'] == transaction['recipient']):
                                return False
                            transactionnum += 1
                            if((str(transaction['sender']) != "0" or int(transaction['amount']) != 1) and (int(transaction['amount']) != 0)):
                                amount = 0
                                existflag = False
                                for blocks in chain:
                                    for ptransaction in blocks['transactions']:
                                        if(transaction['recipient'] == ptransaction['sender']):
                                            existflag = True
                                        if(str(transaction['sender']) == str(ptransaction['sender'])):
                                            if(str(transaction['signature']) == str(ptransaction['signature'])):
                                                transactionnumb += 1
                                        if (str(transaction['sender']) == str(ptransaction['sender'])):
                                            amount -= int(ptransaction['amount'])
                                        if (str(transaction['sender']) == str(ptransaction['recipient'])):
                                            amount += int(ptransaction['amount'])
                                if(existflag == False):
                                    return False
                                if(amount < 0):
                                    return False
                                importedpublickey = RSA.importKey(transaction['sender'])
                                signerpub = PKCS1_v1_5.new(importedpublickey)
                                digestpub = SHA256.new()
                                digestpub.update(bytes(str(transaction['sender'])+str(transaction['recipient'])+str(transaction['amount'])+str(transaction['time']), encoding='utf-8')) 
                                if(signerpub.verify(digestpub, transaction['signature'].encode('ISO-8859-1')) == False):
                                    return False
                            else:
                                if(int(transaction['amount']) == 0):
                                    nicknamecheck += 1
                                    nicknames.append(transaction['recipient'])
                                if(j == length):
                                    if(int(transaction['amount']) == 1):
                                        if(chain[length-1]['solved_by'] != transaction['recipient']):
                                            return False
                                mined += 1
                        if(nicknamecheck > len(nicknames)):
                            return False
                    for x in range(len(nicknames)):
                        for y in range(len(nicknames)):
                            if(nicknames[x] == nicknames[y] and x != y):
                                return False
                    if(transactionnum < transactionnumb):
                        return False
                    if(mined>length):
                        return False
                    max_length = length
                    new_chain = chain
        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            for blocks in new_chain:
                for ptransaction in blocks['transactions']:
                    for i in range(len(self.current_transactions)):
                        if(str(self.current_transactions[i-1]['sender']) == str(ptransaction['sender'])):
                            if(str(self.current_transactions[i-1]['signature']) == str(ptransaction['signature'])):
                                del self.current_transactions[i-1]
            return True
        return False

    def new_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'solved_by': ""
        }
        # Reset the current list of transactions
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, time, signature):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'time': time,
            'signature': signature
        })

        return self.last_block['index'] + 1

    def get_coin(self, address):
        amount = 0
        for blocks in blockchain.chain:
            for transaction in blocks['transactions']:
                if (address == transaction['sender']):
                    amount -= int(transaction['amount'])
                if (address == transaction['recipient']):
                    amount += int(transaction['amount'])
        for transactions in self.current_transactions:
            if (address == transactions['sender']):
                amount -= int(transactions['amount'])
            if (address == transactions['recipient']):
                amount += int(transactions['amount'])
        return amount
    
    def resolve_transactions(self):
        for node in self.nodes:
            response = requests.get(f'http://{node}/transactions/get')
            if response.status_code == 200:
                incoming_response = response.json()[:]
                for itransaction in incoming_response:
                    if (itransaction['amount'] == ""):
                        continue
                    if (int(itransaction['amount']) < 0):
                        continue
                    if (itransaction['sender'] == itransaction['recipient']):
                        continue
                    myflag = False #check if they have been initialized into the blockchain or if transaction was already recieved
                    for blocks in blockchain.chain:
                        amount = 0
                        for transaction in blocks['transactions']:
                            if(str(transaction['sender'] == itransaction['sender'])):
                                if(str(transaction['signature']) == str(itransaction['signature'])):
                                    return False
                            if (str(itransaction['sender']) == str(transaction['sender'])):
                                amount -= int(transaction['amount'])
                            if (str(itransaction['sender']) == str(transaction['recipient'])):
                                amount += int(transaction['amount'])
                            for ourtransaction in self.current_transactions:
                                if (str(itransaction['sender']) == str(ourtransaction['sender'])):
                                    amount -= int(ourtransaction['amount'])
                                if (str(itransaction['sender']) == str(ourtransaction['recipient'])):
                                    amount += int(ourtransaction['amount'])
                            if(transaction['sender'] == itransaction['recipient']):
                                myflag = True
                    for ourtransaction in self.current_transactions:
                        if(ourtransaction['sender'] == itransaction['recipient']):
                            myflag = True
                    if(int(itransaction['amount']) == 0):
                        myflag = True
                    for ourtransactions in self.current_transactions:
                        if(ourtransactions['sender'] == itransaction['sender']):
                            if(ourtransactions['recipient'] == itransaction['recipient']):
                                if(ourtransactions['amount'] == itransaction['amount']):
                                    if(ourtransactions['time'] == itransaction['time']):
                                        myflag = False
                                        break
                    if(myflag == False):
                        continue
                    if (amount >= int(itransaction['amount'])):
                        rsapubkey = RSA.importKey(itransaction['sender'].encode('ISO-8859-1')) 
                        signerpub = PKCS1_v1_5.new(rsapubkey) 
                        digestpub = SHA256.new() 
                        # Assumes the data is base64 encoded to begin with
                        digestpub.update(bytes(str(itransaction['sender'])+str(itransaction['recipient'])+str(itransaction['amount'])+str(itransaction['time']), encoding='utf-8'))
                        if(signerpub.verify(digestpub, itransaction['signature'].encode('ISO-8859-1')) == False):
                            return False
                        #take transaction off chain
                    else:
                        return False
                    blockchain.current_transactions.append(itransaction)
        return True

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000" #add zeros to make exponentially harder

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
#node_identifier = str(uuid4()).replace('-', '')
# Instantiate the Blockchain
 
blockchain = Blockchain()

node_identifier = blockchain.public_key.decode('ISO-8859-1')

def updateBlockchain():
    while(True):
        try:
            blockchain.resolve_conflicts()
            time.sleep(5)
        except:
            time.sleep(5)

def updateTransactions():
    while(True):
        try:
            blockchain.resolve_transactions()
            time.sleep(5)
        except:
            time.sleep(5)

def addMainNode():
    while(True):
        try:
            if(blockchain.register_node('http://127.0.0.1:80')):
                break
        except:
            time.sleep(3)
    print("node added")
    
def getNodes():
    while(True):
        try:
            for node in blockchain.nodes:
                response = requests.get(f'http://{node}/nodes/get')
                if response.status_code == 200:
                    for nodes in response.json():
                        thisflag = False
                        for nodeses in blockchain.nodes:
                            if(nodeses == nodes):
                                thisflag = True
                                break
                        if(thisflag == False):
                            blockchain.nodes.append(nodes)
            time.sleep(10)
        except:
            time.sleep(10)

def saveBlockchain():
    while(True):
        try:
            privatekey = open("blockchain.save", 'wb')
            privatekey.write(str(blockchain.chain).encode('ISO-8859-1'))
            privatekey.close()
            time.sleep(20)
        except:
            print("blockchain not saved")
            time.sleep(20)

try:
    blockchain.register_node('http://127.0.0.1:80')
except:
    print("nodes not added")
"""
try:
    blockchain.register_node('http://127.0.0.1:8080')
except:
    print("nodes not added")
"""
try:
    blockchain.resolve_conflicts()
except:
    print("no chain found")
nicknameflag = False
for block in blockchain.chain:
    for transaction in block['transactions']:
        if(str(transaction['sender']) == str(node_identifier)):
            if(int(transaction['amount']) == 0):
                nicknameflag = True
if(nicknameflag == False):
    nickname = input("what is your name?\n")

def initializeNode():
    while(True):
        myflag = False
        for block in blockchain.chain:
            for transaction in block['transactions']:
                    if(str(transaction['sender']) == str(node_identifier)):
                        myflag = True
        for transaction in blockchain.current_transactions:
            if(str(transaction['sender']) == str(node_identifier)):
                myflag = True
        if(myflag == False):
            sender = node_identifier
            recipient = nickname
            amount = 0
            currenttime = time.time()
            data = bytes(str(sender)+str(recipient)+str(amount)+str(currenttime), encoding='utf-8')
            rsakey = RSA.importKey(blockchain.private_key) 
            signer = PKCS1_v1_5.new(rsakey)
            digest = SHA256.new()
            digest.update(data)
            signature = signer.sign(digest)
            signature = signature.decode('ISO-8859-1')
            blockchain.new_transaction(sender, recipient, amount, currenttime, signature)
        time.sleep(20)

thread_list = []
updateBlockchainThread = threading.Thread(target=updateBlockchain)
thread_list.append(updateBlockchainThread)
updateTransactionsThread = threading.Thread(target=updateTransactions)
thread_list.append(updateTransactionsThread)
addMainNode = threading.Thread(target=addMainNode)
thread_list.append(addMainNode)
initializeNodeThread = threading.Thread(target=initializeNode)
thread_list.append(initializeNodeThread)
saveBlockchainThread = threading.Thread(target=saveBlockchain)
thread_list.append(saveBlockchainThread)
getOtherNodesThread = threading.Thread(target=getNodes)
thread_list.append(getOtherNodesThread)
for thread in thread_list:
    thread.start()

@app.route('/', methods=['GET'])
def indexstuff():
    return render_template('homepage.html', mycoin=blockchain.get_coin(node_identifier))

@app.route('/mine', methods=['GET'])
def mine():
    blockchain.chain[len(blockchain.chain)-1]['solved_by'] = node_identifier
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)
    for transaction in blockchain.current_transactions:
        for ztransaction in blockchain.current_transactions:
            if(transaction['sender'] == ztransaction['sender'] and int(transaction['amount']) == 0 and int(ztransaction['amount']) == 0 and ztransaction['time'] != transaction['time']):
                blockchain.current_transactions.remove(transaction)
        amount = 0
        if (int(transaction['amount']) < 0):
            blockchain.current_transactions.remove(transaction)
        for blocks in blockchain.chain:
            for ptransaction in blocks['transactions']:
                if (ptransaction['sender'] == transaction['sender'] and ptransaction['signature'] == transaction['signature']):  
                    blockchain.current_transactions.remove(transaction)
                if (transaction['sender'] == ptransaction['sender']):
                    amount -= int(ptransaction['amount'])
                if (transaction['sender'] == ptransaction['recipient']):
                    amount += int(ptransaction['amount'])
        for ttransaction in blockchain.current_transactions:
            if(ttransaction['sender'] != transaction['sender'] and ttransaction['signature'] != transaction['signature']):
                if (transaction['sender'] == ttransaction['sender']):
                    amount -= int(ttransaction['amount'])
                if (transaction['sender'] == ttransaction['recipient']):
                    amount += int(ttransaction['amount'])
        if (amount < int(transaction['amount'])):
            blockchain.current_transactions.remove(transaction)
            #take transaction off chain
    sender = "0"
    recipient = node_identifier
    amount = 1
    currenttime = time.time()
    data = bytes(str(sender)+str(recipient)+str(amount)+str(currenttime), encoding='utf-8')
    rsakey = RSA.importKey(blockchain.private_key) 
    signer = PKCS1_v1_5.new(rsakey) 
    digest = SHA256.new() 
    digest.update(data) 
    signature = signer.sign(digest)
    signature = signature.decode('ISO-8859-1')
    blockchain.new_transaction(
        sender=sender,
        recipient=recipient,
        amount=1,
        time=currenttime,
        signature=signature
    )
    #blockchain.new_transaction(sender="0",recipient=node_identifier,amount=1)
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return render_template('mine.html', response=response), 200

@app.route('/transactions/new', methods=['POST','GET'])
def new_transaction():
    if(request.method == 'POST'):
        sender = node_identifier
        recipient = ""
        for block in blockchain.chain:
            for transaction in block['transactions']:
                if(transaction['recipient'] == request.form['recipient']):
                    recipient = transaction['sender']
        if(recipient == ""):
            return "Invalid Name"
        if(recipient == sender):
            return "you cannot send money to yourself"
        amount = request.form['amount']
        if(amount == "0" or amount == ""):
            return "you have to send a greater amount than 0"
        if(int(amount) > blockchain.get_coin(node_identifier)):
            return "you do not have enough money"
        currenttime = time.time()
        data = bytes(str(sender)+str(recipient)+str(amount)+str(currenttime), encoding='utf-8')
        rsakey = RSA.importKey(blockchain.private_key)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        digest.update(data)
        signature = signer.sign(digest)
        signature = signature.decode('ISO-8859-1')
        blockchain.new_transaction(sender, recipient, amount, currenttime, signature)
        return render_template('transaction.html', mycoin=blockchain.get_coin(node_identifier))
    return render_template('transaction.html', mycoin=blockchain.get_coin(node_identifier))

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400
    for node in nodes:
        blockchain.register_node(node)
    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/get', methods=['GET'])
def get_otherNodes():
    thisflag = False
    for node in blockchain.nodes:
        if(node == request.remote_addr):
            thisflag = True
    if(thisflag == False):
        blockchain.nodes.append(request.remote_addr)
    return jsonify(blockchain.nodes)

@app.route('/transactions/get', methods=['GET'])
def get_transaction():
    return jsonify(blockchain.current_transactions)

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
    