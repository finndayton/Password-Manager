"use strict";

/********* External Imports ********/

const {byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray, stringToByteArray } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Return Type: void
   */

  //pass in salt, keys
  constructor() {
    this.data = { 
      /* Store member variables that are intended to be public here
         (i.e. information that will not compromise security if an adversary sees) */
         salt_master_key: null, //used to generate the master_key
         salt_mac: null, //used to generate mac_key
         salt_aes: null, //use to generate aes_key
         password_sig: null,
         kvs_salts: {}, //each password must have its own salt, or the system will leak information about aes_key
         kvs: {} //this is empty to start, but will get filled up  

    };
    this.secrets = { 
      /* Store member variables are intended to be private here
         (information that an adversary should NOT see). */
         mac_key: null,
         aes_key: null,
         kvs_hash: null
    };
    this.data.version = "CS 255 Password Manager v1.0";

    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;

  };

  /** 
    * Creates an empty keychain with the given password. Once the constructor
    * has finished, the password manager should be in a ready state.
    *
    * Build the secret keys / materials here then pass them in as parameters to the constructor
    * 
    * Arguments:
    *   password: string
    * Return Type: keychain object
    */ 

  static async keyDerivation(password){
    let salt_master_key = genRandomSalt();
    let salt_mac = genRandomSalt();
    let salt_aes = genRandomSalt();
    
    //key_material is a new CryptoKey, an object representing keys in subtle
    const key_material = await subtle.importKey(
      "raw",
      password,
      "PBKDF2",
      false,
      ["deriveKey"] 
    );
    
    //key is a CryptoKey object representing the new key.
    const master_key = await subtle.deriveKey(
      {
        "name": "PBKDF2",
        salt: salt_master_key,
        "iterations": Keychain.PBKDF2_ITERATIONS,
        "hash": "SHA-256"
      },
      key_material,
      { "name": "HMAC", "hash": "SHA-256", "length": 256}, //derivedKeyAlgorithm -- the algorithm the dervied key will be used for
      false, //unsure what to select 
     ["sign", "verify"] //keyUsages -- what can be done with the derived key? Whatever is here must be allowed by derivedKeyAlgorithm
    );

    const raw_mac_key = await subtle.sign("HMAC", master_key, salt_mac);
    const raw_aes_key = await subtle.sign("HMAC", master_key, salt_aes);

    //use import to convert these two arrayBuffers to cryptoKeys (what we need)
    const mac_key = await subtle.importKey(
      "raw",
      raw_mac_key,
      { name:"HMAC", hash: "SHA-256"}, //algorithm -- a dictionary or string defining the type of key we want and providing extra algo-specific params 
      false,
      ["sign", "verify"] //keyUsages -- what can be done with the key?
    );

    const aes_key = await subtle.importKey(
      "raw",
      raw_aes_key,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"] 
    );

    return {
      salt_master_key:salt_master_key,
      salt_mac: salt_mac,
      salt_aes: salt_aes,
      key_material: key_material,
      master_key: master_key,
      raw_aes_key: raw_aes_key,
      raw_mac_key: raw_mac_key,
      mac_key: mac_key,
      aes_key: aes_key
    }
  }

  //end user calls this 
  // return new KeyChain object
  static async init(password) {
    //use this password to generate the secret keys 
    //pass the password and a salt into PBKDF2 to generate the raw key, pass this to the constructor. 
    //make a random salt. 
    const key_data = await Keychain.keyDerivation(password)

    const keychain_instance = new Keychain();

    keychain_instance.secrets.mac_key = key_data.mac_key;
    keychain_instance.secrets.aes_key = key_data.aes_key;
    keychain_instance.secrets.kvs_hash = byteArrayToString(await subtle.digest("SHA-256", JSON.stringify(keychain_instance.data.kvs)));

    keychain_instance.data.salt_master_key = key_data.salt_master_key;
    keychain_instance.data.salt_mac = key_data.salt_mac;
    keychain_instance.data.salt_aes = key_data.salt_aes;

    //use the master_key to sign the password and store the signature in .data 
    keychain_instance.data.password_sig = bufferToUntypedArray(await subtle.sign("HMAC", key_data.master_key, "hello"));
  
    return keychain_instance;
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. We can assume that
    * the representation passed to load is well-formed (i.e., it will be f
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string JSON encoding of password manager
    *   trustedDataCheck: SHA-256 checksum (as a string)
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    
    //First, check is there was tampering
    if (trustedDataCheck !== null) {
      if (trustedDataCheck !== byteArrayToString(await subtle.digest("SHA-256", repr))) { //The Node implementation of subtle will automatically convert strings (repr in this case) specified as input parameters into their corresponding ArrayBuffer forms.
        throw "trustedDataCheck integrity test failed in load()";
      }
    }
      
      //extract the info in the password manager 
      let password_manager = JSON.parse(repr);

      /*
      * Second, verify the provided password is correct. 
      * re-derive the same key used to sign the password in init()
      * this key it found by 
      *  1) importing the password 
      *  2) deriving a key from this Ã¯Â¼Ë†using salt_master_key)
      *  3) HMAC signing with salt_mac 
      *  4) importing again this to get a CryptoKey object
      * Then we use this key to verify the password. 
      */

      //key derivation boilerplate copied from init()
      const key_material = await subtle.importKey(
        "raw",
        password,
        "PBKDF2",
        false,
        ["deriveKey"] 
      );
      
      const master_key = await subtle.deriveKey(
        {
          "name": "PBKDF2",
          salt: password_manager.salt_master_key,
          "iterations": Keychain.PBKDF2_ITERATIONS,
          "hash": "SHA-256"
        },
        key_material,
        { "name": "HMAC", "hash": "SHA-256", "length": 256}, 
        false, 
       ["sign", "verify"] 
      );
  
      const raw_mac_key = await subtle.sign("HMAC", master_key, password_manager.salt_mac);
      const raw_aes_key = await subtle.sign("HMAC", master_key, password_manager.salt_aes);

      const mac_key = await subtle.importKey(
        "raw",
        raw_mac_key,
        { name:"HMAC", hash: "SHA-256"}, 
        false,
        ["sign", "verify"]
      );

      const aes_key = await subtle.importKey(
        "raw",
        raw_aes_key,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"] 
      );

      // const key_data = await Keychain.keyDerivation(password)

      const verify_result = await subtle.verify("HMAC", master_key, untypedToTypedArray(password_manager.password_sig), "hello"); 

      //password is invalid
      if (!verify_result) throw "Password provided to load() is invalid :("
      let keychain_instance = new Keychain();

      //insert data + secrets
      keychain_instance.data = password_manager;

      keychain_instance.secrets.mac_key = mac_key;
      keychain_instance.secrets.aes_key = aes_key;
      keychain_instance.secrets.kvs_hash = byteArrayToString(await subtle.digest("SHA-256", JSON.stringify(keychain_instance.data.kvs)));

      //the keychain is now ready to use
      keychain_instance.ready = true;

      return keychain_instance;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 

  //need stored as an untyped array. 
  async dump() {
    if (!this.ready) return null;

    let dump_data = this.data;

    //whatever we're calling JSON.stringify() on should be an untypedArray
    const serialized = JSON.stringify(dump_data);
    const checksum = byteArrayToString(await subtle.digest("SHA-256", serialized));
    return [serialized, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if (!this.ready) throw "Keychain not initialized";

    //rollback attack check
    //compute new sha256 hash over the kvs 
    const new_kvs_hash = byteArrayToString(await subtle.digest("SHA-256", JSON.stringify(this.data.kvs)));
    if(new_kvs_hash !== this.secrets.kvs_hash) throw "rollback tampering detected"

    const encrypted_domain = byteArrayToString(await subtle.sign("HMAC", this.secrets.mac_key, name));

    //the (encrypted) domain name does not exist 
    if (!(encrypted_domain in this.data.kvs)) return null;
  
    //extract the password associated with this domain and decrypt it
    const encrypted_password = untypedToTypedArray(this.data.kvs[encrypted_domain]); //a string, According to part 3.3 of spec, Node will automatically convert this input parameter into its corresponding ArrayBuffer form.
    const decrypted_password = await subtle.decrypt({name: "AES-GCM", iv: this.data.kvs_salts[encrypted_domain], additionalData: name}, 
                                                     this.secrets.aes_key, 
                                                     encrypted_password);

    return Keychain.unpad(byteArrayToString(decrypted_password));  
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (!this.ready) throw "Keychain not initialized";

    //check for rollback attack
    const new_kvs_hash = byteArrayToString(await subtle.digest("SHA-256", JSON.stringify(this.data.kvs)));
    // console.log("new_kvs_hash = ", new_kvs_hash, " this.secrets.kvs_hash = ", this.secrets.kvs_hash);
    if(new_kvs_hash !== this.secrets.kvs_hash) throw "rollback tampering detected"

    const encrypted_domain = byteArrayToString(await subtle.sign("HMAC", this.secrets.mac_key, name));
    //this salt is bound to this password and can only every be used with this particular password
    const password_salt = genRandomSalt(12); //https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams says salt should be 96 bits = 12 bytes long
    
    const encrypted_password = bufferToUntypedArray(await subtle.encrypt({name: "AES-GCM", iv: password_salt, additionalData: name}, 
                                                     this.secrets.aes_key, 
                                                     Keychain.pad(value, 64, "\0")));
    
    this.data.kvs[encrypted_domain] = encrypted_password;

    //add the salt for this particular domain / password combo
    this.data.kvs_salts[encrypted_domain] = password_salt;

    //update kvs hash
    this.secrets.kvs_hash = byteArrayToString(await subtle.digest("SHA-256", JSON.stringify(this.data.kvs)));
  };


   static pad (value, n, pad){
    var t = value;
    if (n > value.length)
        for (var i = 0; i < n - value.length; i++)
            if (i === 0){
              t+= "1" //pad always starts with 1, as seen in lecture. 
            } else{
              t += pad;
            }
    return t;
  };

  static unpad(value) {
      var i = value.length;
      while (i && value[i - 1] == "\0")
          --i
      return value.substr(0, i-1)
  }


  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (!this.ready) throw "Keychain not initialized";
    const encrypted_domain = byteArrayToString(await subtle.sign("HMAC", this.secrets.mac_key, name));

    if (!(encrypted_domain in this.data.kvs)) return false;

    delete this.data.kvs[encrypted_domain]
    delete this.data.kvs_salts[encrypted_domain];

    //update the kvs_hash
    this.secrets.kvs_hash = byteArrayToString(await subtle.digest("SHA-256", JSON.stringify(this.data.kvs)));
    
    return true;
  };

  static get PBKDF2_ITERATIONS() { return 100000; }
};

module.exports = {
  Keychain: Keychain
}
