const systemKey = "secure-vault-core";

let vaultKey=null;
let vaultMemory=null;

/* KEY */
async function deriveKey(pin,salt){
 const enc=new TextEncoder();

 const baseKey=await crypto.subtle.importKey(
  "raw",
  enc.encode(pin+systemKey),
  "PBKDF2",
  false,
  ["deriveKey"]
 );

 return crypto.subtle.deriveKey(
  {name:"PBKDF2",salt:salt,iterations:100000,hash:"SHA-256"},
  baseKey,
  {name:"AES-GCM",length:256},
  false,
  ["encrypt","decrypt"]
 );
}

/* CREATE */
async function createVault(pin){
 const salt=crypto.getRandomValues(new Uint8Array(16));
 vaultKey=await deriveKey(pin,salt);
 vaultMemory={entries:[]};
 await saveVault();
 localStorage.setItem("vaultSalt",JSON.stringify(Array.from(salt)));
}

/* UNLOCK */
async function unlockVault(pin){
 const saltStored=localStorage.getItem("vaultSalt");
 const vaultStored=localStorage.getItem("vaultSecure");
 if(!saltStored||!vaultStored) return false;

 const salt=new Uint8Array(JSON.parse(saltStored));
 vaultKey=await deriveKey(pin,salt);

 try{
  const vaultObj=JSON.parse(vaultStored);
  const iv=new Uint8Array(vaultObj.iv);
  const data=new Uint8Array(vaultObj.data);

  const decrypted=await crypto.subtle.decrypt(
   {name:"AES-GCM",iv:iv},
   vaultKey,
   data
  );

  vaultMemory=JSON.parse(new TextDecoder().decode(decrypted));
  return true;
 }catch{ return false;}
}

/* SAVE */
async function saveVault(){
 if(!vaultKey||!vaultMemory) return;

 const iv=crypto.getRandomValues(new Uint8Array(12));
 const encrypted=await crypto.subtle.encrypt(
  {name:"AES-GCM",iv:iv},
  vaultKey,
  new TextEncoder().encode(JSON.stringify(vaultMemory))
 );

 localStorage.setItem("vaultSecure",JSON.stringify({
  iv:Array.from(iv),
  data:Array.from(new Uint8Array(encrypted))
 }));
}
