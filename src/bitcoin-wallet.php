<?php

require_once 'vendor/autoload.php';

use BitWasp\Bitcoin\Address\AddressCreator;
use BitWasp\Bitcoin\Address\PayToPubKeyHashAddress;
use BitWasp\Bitcoin\Address\ScriptHashAddress;
use BitWasp\Bitcoin\Address\SegwitAddress;
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Key\Factory\PrivateKeyFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39Mnemonic;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Network\NetworkFactory;
use BitWasp\Bitcoin\Script\WitnessProgram;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\ScriptType;
use BitWasp\Bitcoin\Script\P2shScript;
use BitWasp\Bitcoin\Transaction\Factory\TxBuilder;
use BitWasp\Bitcoin\Transaction\Factory\Signer;
use BitWasp\Buffertools\Buffer;
use BitWasp\Bitcoin\Transaction\OutPoint;

Bitcoin::setNetwork(NetworkFactory::bitcoinTestnet());
$network = Bitcoin::getNetwork();
$ecAdapter = Bitcoin::getEcAdapter();

function bytes_to_hex($byte_str) {
    return bin2hex($byte_str);
}

// Generate a mnemonic
$random = new Random();
$entropy = $random->bytes(Bip39Mnemonic::MAX_ENTROPY_BYTE_LEN);
$bip39 = MnemonicFactory::bip39();
$mnemonic = $bip39->entropyToMnemonic($entropy);

echo "12 word Mnemonic: $mnemonic\n" . "\n";

// Generate the BIP39 seed from the mnemonic
$seedGenerator = new Bip39SeedGenerator();
$seed = $seedGenerator->getSeed($mnemonic);

// Derive the master key from the seed
$hdFactory = new HierarchicalKeyFactory();
$masterKey = $hdFactory->fromEntropy($seed);

// Derive the purpose key (m/84'/0'/0')
$purposeKey = $masterKey->derivePath("84'/0'/0'");

// Derive the account key (m/84'/0'/0'/0)
$accountKey = $purposeKey->derivePath('0');

// Derive the external key (m/84'/0'/0'/0/0)
$externalKey = $accountKey->derivePath('0');

// Get the public key from the external key
$publicKey = $externalKey->getPublicKey();

// Derive the public key hash
$publicKeyHash = $publicKey->getPubKeyHash();
echo 'Public Key Hash: ' . $publicKeyHash->getHex() . "\n";

// Derive the pay to public key hash address
$p2pkh = new PayToPubKeyHashAddress($publicKeyHash);
$p2pkhAddress = $p2pkh->getAddress($network);
echo 'P2PKH Address: ' . $p2pkhAddress . "\n";

// Derive the redeem script
$preimage = 'Btrust Builders';
$lock_hex = hash('sha256', $preimage);
$redeemScript = ScriptFactory::create()
    ->op('OP_SHA256')
    ->push(Buffer::hex($lock_hex))
    ->op('OP_EQUAL')
    ->getScript();

echo 'Redeem Script: ' . $redeemScript->getHex() . "\n";

// Derive the P2SH address
$p2sh = new ScriptHashAddress($redeemScript->getScriptHash());
$p2shAddress = $p2sh->getAddress($network);
echo 'P2SH Address: ' . $p2shAddress . "\n";

// Derive the native segwit address
$p2wpkhWP = WitnessProgram::v0($publicKeyHash);
$p2wpkh = new SegwitAddress($p2wpkhWP);
$p2wpkhaddress = $p2wpkh->getAddress($network);
echo 'Native SegWit / P2WPKH Address: ' . $p2wpkhaddress . "\n";

// Derive the Pay to Witness Script Hash address
$p2wshWP = WitnessProgram::v0($redeemScript->getWitnessScriptHash());
$p2wsh = new SegwitAddress($p2wshWP);
$p2wshAddress = $p2wsh->getAddress($network);
echo 'P2WSH Address: ' . $p2wshAddress . "\n";

// Address used: tb1q6qrae368rg5jpze6huc76qg37ecmucmhpjqa9t (Native Segwit)
// Construct a transaction
$addrCreator = new AddressCreator();
$txID = 'e31d31c51f01f8e99d9f4c7ddac6b5554c7d119907c3807e388a1f2c793fdcb0';
$spendOutput = new Outpoint(Buffer::hex('e31d31c51f01f8e99d9f4c7ddac6b5554c', 32), 0);
$recipient = $p2shAddress;

// Construct a transaction
$tx = (new TxBuilder())
    ->spendOutPoint($spendOutput)
    ->payToAddress(10000, $p2pkh)
    ->get();

// Sign the transaction
$signer = new Signer($tx, $ecAdapter);
$signedTx = $signer->sign(0, $externalKey, $txID);

echo $signedTx->getHex() . "\n";

?>
