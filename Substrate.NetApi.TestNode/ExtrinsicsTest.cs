﻿using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using Substrate.NetApi.Model.Types.Base;

using Substrate.NetApi.Model.Extrinsics;
using Schnorrkel.Keys;
using System;
using Newtonsoft.Json.Linq;
using NUnit.Framework.Internal;

namespace Substrate.NetApi.TestNode
{
    public class ExtrinsicTest
    {
        //Tested by
        //Gear Node version 1.0.1 - 3ee1edde2f8
        protected const string WebSocketUrl = "ws://127.0.0.1:9944";

        protected SubstrateClient _substrateClient;

        [SetUp]
        public async Task ConnectAsync()
        {
            await _substrateClient.ConnectAsync();
        }

        [TearDown]
        public async Task CloseAsync()
        {
            await _substrateClient.CloseAsync();
        }

        [OneTimeSetUp]
        public void CreateClient()
        {
            _substrateClient = new SubstrateClient(new Uri(WebSocketUrl), ChargeTransactionPayment.Default());
        }

        [OneTimeTearDown]
        public void DisposeClient()
        {
            _substrateClient.Dispose();
        }

        [Test]
        public async Task GetSignedTxAsync()
        {

            var miniSecretAlice = new MiniSecret(Utils.HexToByteArray("0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"), ExpandMode.Ed25519);
            //var alice = Account.Build(KeyType.Sr25519, miniSecretAlice.ExpandToSecret().ToBytes(), miniSecretAlice.GetPair().Public.Key);
            var keyPairAlice = miniSecretAlice.GetPair();
            var addressAlice = Utils.GetAddressFrom(miniSecretAlice.GetPair().Public.Key);
            var addressAliceHex = "00" + Utils.Bytes2HexString(Base58Local.Decode(addressAlice)).ToLower().Substring(4, 64);
            Console.WriteLine($"addressAliceHex:\n{addressAliceHex}");

            var miniSecretBob = new MiniSecret(Utils.HexToByteArray("0x398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89"), ExpandMode.Ed25519);
            //var bob = Account.Build(KeyType.Sr25519, miniSecretBob.ExpandToSecret().ToBytes(), miniSecretBob.GetPair().Public.Key);
            //var keyPairBob = miniSecretAlice.GetPair();
            var addressBob = Utils.GetAddressFrom(miniSecretBob.GetPair().Public.Key);
            var addressBobHex = "00" + Utils.Bytes2HexString(Base58Local.Decode(addressBob)).ToLower().Substring(4, 64);
            Console.WriteLine($"addressBobHex:\n{addressBobHex}");


            //Payload
            //method 0x0500008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a489101
            //era 0x7500
            //nonce 0x0c
            //tip 0x00
            //specVersion 0xf2030000
            //transactionVersion 0x01000000
            //genesisHash 0x1f7d7c86886305a96d76c98d49fb2bb7df4f35d5753498e63431889b0e014609
            //blockHash 0xe7e76da14575d1c48e14b16ab945906f7c14c9b4c40a00abf61d47cb03f41029

            var transfer = 100;
            var transferHex = Utils.Bytes2HexString(new CompactInteger(transfer).Encode()).ToLower().Substring(2);
            Console.WriteLine($"transferHex:\n{transferHex}");
            var methodHex = "0500" + addressBobHex + transferHex;


            var finalizedHeader = await _substrateClient.Chain.GetHeaderAsync();
            var lastBlockNumber1 = finalizedHeader.Number.Value;
            var era = Era.Create(64, finalizedHeader.Number.Value);
            var eraHex = Utils.Bytes2HexString(era.Encode()).ToLower().Substring(2);
            Console.WriteLine($"eraHex:\n{eraHex}");

            var nonce = await _substrateClient.System.AccountNextIndexAsync(addressAlice, CancellationToken.None);
            var nonceHex = Utils.Bytes2HexString(new CompactInteger(nonce).Encode()).ToLower().Substring(2);
            Console.WriteLine($"nonceHex:\n{nonceHex}");

            var tip = 0;
            var tipHex = Utils.Bytes2HexString(new CompactInteger(tip).Encode()).ToLower().Substring(2);
            Console.WriteLine($"tipHex:\n{tipHex}");


            var runtimeVersion_1 = await _substrateClient.State.GetRuntimeVersionAsync();
            var specVersionHex =
                Utils.Bytes2HexString(BitConverter.GetBytes(runtimeVersion_1.SpecVersion)).ToLower().Substring(2);
            Console.WriteLine($"specVersionHex:\n{specVersionHex}");
            var transactionVersionHex =
                Utils.Bytes2HexString(BitConverter.GetBytes(runtimeVersion_1.TransactionVersion)).ToLower().Substring(2);
            Console.WriteLine($"transactionVersionHex:\n{transactionVersionHex}");

            var genesis = new BlockNumber();
            genesis.Create(0);
            var genesisHash = await _substrateClient.Chain.GetBlockHashAsync(genesis, CancellationToken.None);
            var genesisHashHex = genesisHash.Value.ToLower().Substring(2);
            Console.WriteLine($"genesisHashHex:\n{genesisHashHex}");

            var blockHash = await _substrateClient.Chain.GetBlockHashAsync();
            var blockHashHex = blockHash.Value.ToLower().Substring(2);
            Console.WriteLine($"blockHashHex:\n{blockHashHex}");

            var payload_hex = "0x" + methodHex + eraHex + nonceHex +
                tipHex + specVersionHex + transactionVersionHex +
                genesisHashHex + blockHashHex;

            var payload = Utils.HexToByteArray(payload_hex);

            /// Payloads longer than 256 bytes are going to be `blake2_256`-hashed.
            if (payload.Length > 256)
            {
                Assert.True(false);//not tested
                payload = HashExtension.Blake2(payload, 256);
            }

            // sign payload with the Sr25519
            var simpleSign = Schnorrkel.Sr25519v091.SignSimple(keyPairAlice, payload);
            var simpleSignHex = "01" + Utils.Bytes2HexString(simpleSign).ToLower().Substring(2);
            Console.WriteLine($"simpleSignHex:\n{simpleSignHex}");

            //compact length 0x3102
            //version 84
            //signer 0x00d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
            //signature 0x012a3cfc6276f33837a68145f398663f419ef90f27b77ccb67756138db2545d560da748231a05d55f9a39efde9507101ef58657314ad0bb81c7b06a49805fe9380
            //era 0xa500
            //nonce 0x24
            //tip 0x000  
            //method 0x0500008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a489101

            var paramsHex = "84" + addressAliceHex + simpleSignHex +
                eraHex + nonceHex + tipHex + methodHex;

            var lengthCompact = Utils.Bytes2HexString(new CompactInteger(paramsHex.Length / 2).Encode()).ToLower().Substring(2);

            paramsHex = "0x" + lengthCompact + paramsHex;
            Console.WriteLine($"paramsHex:\n{paramsHex}");

            var result = await _substrateClient.Author.SubmitExtrinsicAsync(paramsHex, CancellationToken.None);




        }

        [Test]
        public async Task GetStorageAsync()
        {
            //TODO function encodeStorageKey
            var module = "26aa394eea5630e07c48ae0c9558cef7";
            var method = "b99d880ec681799c0cf30e8886371da9";
            //blake2_128concat(accountid32)
            //Bob address hex 0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48
            var addressBobHex = "4f9aea1afa791265fae359272badc1cf8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48";
            var storageKey = "0x" + module + method + addressBobHex;

            var storage = await _substrateClient.InvokeAsync<JArray>("state_queryStorageAt", new object[] { new object[] { storageKey } }, CancellationToken.None);


            var paramHex = (string)storage[0]["changes"][0][1];
            var balanceHex = "0x13" + paramHex.Substring(34, 32);
            var balanceArr = Utils.HexToByteArray(balanceHex);
            var balance = CompactInteger.Decode(balanceArr);
            Console.WriteLine($"balance:\n{balance}");

        }
    }

}







