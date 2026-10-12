import assert from 'node:assert/strict';
import test from 'node:test';
import {Wallet} from 'ethers';
import {signWithWallet} from '../scripts/sign-with-wallet.mjs';
const mandate={chain:'base',address:'0x0000000000000000000000000000000000000009',allowedContracts:['0x0000000000000000000000000000000000000002'],maxAmountWei:'10',expiresAt:'2097-01-01'};
test('transaction fields cannot override checked signing authority',async()=>{
 for(const transaction of [{to:'0x0000000000000000000000000000000000000099'},{value:'11'},{chainId:1},{from:'0x0000000000000000000000000000000000000088'},{authorizationList:[]}]){
  const result=await signWithWallet({chain:'base',mandate,payload:{chain:'base',contract:mandate.allowedContracts[0],valueWei:'1',transaction},keystorePath:'/nonexistent',passphrase:'irrelevant',now:'2096-01-01'});
  assert.equal(result.signed,false);assert.match(result.reason,/differs|unmandated/);
 }
});

test('custody address must match the granted wallet',async()=>{
 const key='FLEET_SIGNER_BINDING_TEST_KEY';const prior=process.env[key];process.env[key]=Wallet.createRandom().privateKey;
 try{
  const result=await signWithWallet({chain:'base',mandate,payload:{chain:'base',contract:mandate.allowedContracts[0],valueWei:'1',transaction:{chainId:8453}},custody:{kind:'env-on-host',locator:key},now:'2096-01-01'});
  assert.equal(result.signed,false);assert.match(result.reason,/custodied wallet differs/);
 }finally{if(prior===undefined)delete process.env[key];else process.env[key]=prior;}
});
test('expiry is a closed signing boundary',async()=>{
 const result=await signWithWallet({chain:'base',mandate,payload:{chain:'base',contract:mandate.allowedContracts[0],valueWei:'1'},now:mandate.expiresAt});
 assert.equal(result.signed,false);assert.match(result.reason,/expired/);
});
