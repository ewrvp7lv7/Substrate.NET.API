﻿using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Linq;
using Newtonsoft.Json.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using Substrate.NetApi.Model.Types.Base;
using Substrate.NetApi.Model.Extrinsics;
using Substrate.NetApi.Model.Types;
using Schnorrkel.Keys;
using Schnorrkel;
using Substrate.NetApi.Extensions;

using Substrate.NetApi.Model.Rpc;


namespace Substrate.NetApi.TestNode
{
    public class GearExtrinsicsTest
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


            // Payload for signature:
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
                payload = HashExtension.Blake2(payload, 256);

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
            // TODO function encodeStorageKey
            var module = "26aa394eea5630e07c48ae0c9558cef7";
            var method = "b99d880ec681799c0cf30e8886371da9";
            // blake2_128concat(accountid32)
            // Bob address hex 0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48
            var addressBobHex = "4f9aea1afa791265fae359272badc1cf8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48";
            var storageKey = "0x" + module + method + addressBobHex;

            var storage = await _substrateClient.InvokeAsync<JArray>("state_queryStorageAt", new object[] { new object[] { storageKey } }, CancellationToken.None);


            var paramHex = (string)storage[0]["changes"][0][1];
            var balanceHex = "0x13" + paramHex.Substring(34, 32);
            var balanceArr = Utils.HexToByteArray(balanceHex);
            var balance = CompactInteger.Decode(balanceArr);
            Console.WriteLine($"balance:\n{balance}");

        }

        [Test]
        public async Task GetGearProgramStateAsync()
        {
            // Gear Protocol demo             
            // For test_meta.opt.wasm originally from
            // https://github.com/gear-tech/gear-js/tree/main/api/programs

            // change it!
            var programAddress = "0x1d7b913a1675b58bee9e7efd5aa152245004d6a5e7ed772d3c5749234d834947";

            var argHex = "0x0100000000";//Option<U32> = 0x00

            var state = await _substrateClient.InvokeAsync<JValue>("gear_readState", new object[] { programAddress, argHex, null }, CancellationToken.None);

            var stateHex = (string)state;
            Console.WriteLine($"state:\n{stateHex}");//0x04000000000000000000000000000000000400205375726e616d6530144e616d6530

        }

        [Test]
        public async Task LoadGearProgramTxAsync()
        {
            // Gear Protocol demo             
            // For test_meta.opt.wasm originally from
            // https://github.com/gear-tech/gear-js/tree/main/api/programs

            var miniSecretAlice = new MiniSecret(Utils.HexToByteArray("0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"), ExpandMode.Ed25519);
            //var alice = Account.Build(KeyType.Sr25519, miniSecretAlice.ExpandToSecret().ToBytes(), miniSecretAlice.GetPair().Public.Key);
            var keyPairAlice = miniSecretAlice.GetPair();
            var addressAlice = Utils.GetAddressFrom(miniSecretAlice.GetPair().Public.Key);
            var addressAliceHex = "00" + Utils.Bytes2HexString(Base58Local.Decode(addressAlice)).ToLower().Substring(4, 64);
            Console.WriteLine($"addressAliceHex:\n{addressAliceHex}");


            // Gas_limit:
            var codeBytes = System.IO.File.ReadAllBytes(".\\wasm32-unknown-unknown\\debug\\test_meta.opt.wasm");
            var codeBytesHex = Utils.Bytes2HexString(codeBytes).ToLower().Substring(2);
            var codeLengthCompact = Utils.Bytes2HexString(new CompactInteger(codeBytesHex.Length / 2).Encode()).ToLower().Substring(2);
            codeLengthCompact += codeBytesHex;
            Console.WriteLine($"codeBytes:\n{codeBytesHex.Substring(0, 30)}...");


            // There is a lot Rust-similar types as input for smart-contracts.
            // https://docs.substrate.io/reference/scale-codec/
            // They describes in meta. Here is 8-bit arr as example.
            var initPayloadArr = new byte[] { 1, 2, 3 };
            var initPayloadArrHex = Utils.Bytes2HexString(initPayloadArr).ToLower().Substring(2);
            var initPayloadLengthCompact = Utils.Bytes2HexString(new CompactInteger(initPayloadArrHex.Length / 2).Encode()).ToLower().Substring(2);
            var initPayloadArrHexWL = initPayloadLengthCompact + initPayloadArrHex;
            Console.WriteLine($"initPayloadArrHexWL:\n{initPayloadArrHexWL}");

            var gasResponce = await _substrateClient.InvokeAsync<JObject>("gear_calculateInitUploadGas",
                new object[] {
                    "0x" + addressAliceHex.Substring(2),
                    "0x" + codeBytesHex,
                    "0x" + initPayloadArrHexWL, //0x0c010203
                    0, true
                }, CancellationToken.None);

            var minLimit = (int)gasResponce["min_limit"];
            var minLimitHex = Utils.Bytes2HexString(BitConverter.GetBytes(minLimit)).ToLower().Substring(2);
            var gasLimit = minLimitHex + "00000000";
            Console.WriteLine($"gasLimit:\n{gasLimit}");

            // Method:
            //callIndex 0x6801
            //code 
            //salt 0x50b7e40d52c7d14035848f7e20a8642413cca3dbe3
            //init_payload 0x100c010203
            //gas_limit 0x4bb4464a00000000
            //value 0x00000000000000000000000000000000

            //20-byte random value
            var originalBytes = new byte[20];
            byte[] salt = originalBytes.Populate();
            var saltHex = Utils.Bytes2HexString(salt).ToLower().Substring(2);
            var saltLengthCompact = Utils.Bytes2HexString(new CompactInteger(saltHex.Length / 2).Encode()).ToLower().Substring(2);
            var saltHexWL = saltLengthCompact + saltHex;
            Console.WriteLine($"saltHex:\n{saltHexWL}");


            //ProgramId:
            byte[] prefix = Encoding.ASCII.GetBytes("program_from_user");

            var codeHash = HashExtension.Blake2(codeBytes, 256);

            var idArr = prefix.Concat(codeHash.Concat(salt)).ToArray();

            var programId = Utils.Bytes2HexString(HashExtension.Blake2(idArr, 256)).ToLower();
            Console.WriteLine($"ProgramId:\n{programId}");


            var value = "0x00000000000000000000000000000000".Substring(2);

            var methodHex = "6801" +
                codeLengthCompact +
                saltHexWL +
                "10" + initPayloadArrHexWL + //TODO 10?
                gasLimit +
                value;


            // Payload for signature:
            //method
            //era 0x7500
            //nonce 0x0c
            //tip 0x00
            //specVersion 0xf2030000
            //transactionVersion 0x01000000
            //genesisHash 0x1f7d7c86886305a96d76c98d49fb2bb7df4f35d5753498e63431889b0e014609
            //blockHash 0xe7e76da14575d1c48e14b16ab945906f7c14c9b4c40a00abf61d47cb03f41029


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

            var payload_hex = "0x" +
                methodHex +
                eraHex +
                nonceHex +
                tipHex +
                specVersionHex +
                transactionVersionHex +
                genesisHashHex +
                blockHashHex;

            var payload = Utils.HexToByteArray(payload_hex);

            // Payloads longer than 256 bytes are going to be `blake2_256`-hashed.
            if (payload.Length > 256)
                payload = HashExtension.Blake2(payload, 256);

            // sign payload with the Sr25519
            var simpleSign = Schnorrkel.Sr25519v091.SignSimple(keyPairAlice, payload);
            var simpleSignHex = "01" + Utils.Bytes2HexString(simpleSign).ToLower().Substring(2);
            Console.WriteLine($"simpleSignHex:\n{simpleSignHex}");

            // Extrinsic params:
            //compact length 0x3102
            //version 84
            //signer 0x00d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
            //signature 0x012a3cfc6276f33837a68145f398663f419ef90f27b77ccb67756138db2545d560da748231a05d55f9a39efde9507101ef58657314ad0bb81c7b06a49805fe9380
            //era 0xa500
            //nonce 0x24
            //tip 0x000  
            //method 0x0500008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a489101

            var paramsHex = "84" +
                addressAliceHex +
                simpleSignHex +
                eraHex + nonceHex + tipHex +
                methodHex;

            var lengthCompact = Utils.Bytes2HexString(new CompactInteger(paramsHex.Length / 2).Encode()).ToLower().Substring(2);

            paramsHex = "0x" + lengthCompact + paramsHex;
            Console.WriteLine($"paramsHex:\n{paramsHex.Substring(0, 30)}...");



            //Storage subscription
            var key0 = "0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7";
            var key1 = "0x26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9de1e86a9a8c739864cf3cc5ec2bea59fd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

            var subscriptionIdStorage =
                await _substrateClient.InvokeAsync<string>("state_subscribeStorage", new object[] { new object[] { key0, key1 } }, CancellationToken.None);

            _substrateClient.Listener.RegisterCallBackHandler(subscriptionIdStorage, (string subscriptionIdStorage, StorageChangeSet result) =>
            {
                var programChanged = "6807" + //index of ProgramChanged method
                        programId.Substring(2);

                var param = result.Changes.Where(x => x != null && x[1].IndexOf(programChanged) > -1);

                if (param.Any() && Regex.IsMatch(param.First()[1], (programChanged + "[\\da-e]{14}02000000"), RegexOptions.IgnoreCase))
                    Console.WriteLine("storageUpdate: Program initialized successfully");

            });



            // Subscribtion and listening
            var taskCompletionSource = new TaskCompletionSource<(bool, Hash)>();

            // Program loading and extrinsicUpdate subscription
            var subscriptionId =
                await _substrateClient.InvokeAsync<string>("author_submitAndWatchExtrinsic", new object[] { paramsHex }, CancellationToken.None);

            _substrateClient.Listener.RegisterCallBackHandler(subscriptionId, (string subscriptionId, ExtrinsicStatus extrinsicUpdate) =>
            {
                if (extrinsicUpdate.ExtrinsicState == ExtrinsicState.Finalized ||
                    extrinsicUpdate.ExtrinsicState == ExtrinsicState.Dropped ||
                    extrinsicUpdate.ExtrinsicState == ExtrinsicState.Invalid)
                {
                    taskCompletionSource.SetResult((true, extrinsicUpdate.Hash));
                }


                Console.WriteLine($"extrinsicUpdate:\n{extrinsicUpdate.ExtrinsicState}");
            });

            var finished = await Task.WhenAny(taskCompletionSource.Task, Task.Delay(TimeSpan.FromMinutes(1)));
            Assert.AreEqual(taskCompletionSource.Task, finished, "Test timed out waiting for final callback");

        }

        [Test]
        public async Task Message2ProgramTxAsync()
        {
            // Gear Protocol demo             
            // For test_meta.opt.wasm originally from
            // https://github.com/gear-tech/gear-js/tree/main/api/programs

            var miniSecretAlice = new MiniSecret(Utils.HexToByteArray("0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"), ExpandMode.Ed25519);
            var keyPairAlice = miniSecretAlice.GetPair();
            var addressAlice = Utils.GetAddressFrom(miniSecretAlice.GetPair().Public.Key);
            var addressAliceHex = "00" + Utils.Bytes2HexString(Base58Local.Decode(addressAlice)).ToLower().Substring(4, 64);
            Console.WriteLine($"addressAliceHex:\n{addressAliceHex}");
            
            
            // Change it!
            var programId = "0x208d2436d58640c86dea97ca5a0f8489649d2b8f6f52873b43df07ab2e82ef9f".Substring(2);

            var value = 10_000_000_000_000;
            var valueBI = new System.Numerics.BigInteger(value);
            var valueHex = Utils.Bytes2HexString(new CompactInteger(valueBI).Encode()).ToLower().Substring(4) + "00000000000000000000";
            Console.WriteLine($"valueHex:\n{valueHex}");

            // Payload
            //There is a lot Rust-similar types as input for smart-contracts.
            //https://docs.substrate.io/reference/scale-codec/
            //They describes in meta.
            //const payload = {
            //  One: 'String',
            //};
            var payloadHex = "0x000118537472696e67".Substring(2);

            var payloadLen = payloadHex.Length / 2;
            var payloadCompactLen = Utils.Bytes2HexString(new CompactInteger(payloadLen).Encode()).ToLower().Substring(2);
            Console.WriteLine($"payloadCompactLen:\n{payloadCompactLen}");

            //gas_limit:
            var gasResponce = await _substrateClient.InvokeAsync<JObject>("gear_calculateHandleGas",
                new object[] {
                    "0x" + addressAliceHex.Substring(2),
                    "0x" + programId,
                    "0x" + payloadHex,
                    value,
                    true
                }, CancellationToken.None);

            var minLimit = System.Numerics.BigInteger.Parse((String)gasResponce["min_limit"]);
            var minLimitHex = Utils.Bytes2HexString(new CompactInteger(minLimit).Encode()).ToLower().Substring(4) + "00000000";
            Console.WriteLine($"gasLimit:\n{minLimitHex}");



            // Method
            // callIndex 0x6803,
            // programId (destination) 0xa9cf7cc945f0632a22a7028d8a83a2a153318bb3f4d04d1200afc31ee9a05372
            // payload 0x000118537472696e67
            // gas_limit 1884116246,
            // value 10000000000000,
            //"keep_alive":true

            var keep_alive = "0x00".Substring(2);

            var methodHex = "6803" +
                programId +
                payloadCompactLen +
                payloadHex +
                minLimitHex +
                valueHex +
                keep_alive;

            // Payload for signature:
            //method
            //era 0x7500
            //nonce 0x0c
            //tip 0x00
            //specVersion 0xf2030000
            //transactionVersion 0x01000000
            //genesisHash 0x1f7d7c86886305a96d76c98d49fb2bb7df4f35d5753498e63431889b0e014609
            //blockHash 0xe7e76da14575d1c48e14b16ab945906f7c14c9b4c40a00abf61d47cb03f41029


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

            var payload_hex = "0x" +
                methodHex +
                eraHex +
                nonceHex +
                tipHex +
                specVersionHex +
                transactionVersionHex +
                genesisHashHex +
                blockHashHex;

            var payload = Utils.HexToByteArray(payload_hex);

            // Payloads longer than 256 bytes are going to be `blake2_256`-hashed.
            if (payload.Length > 256)
                payload = HashExtension.Blake2(payload, 256);

            // sign payload with the Sr25519
            var simpleSign = Schnorrkel.Sr25519v091.SignSimple(keyPairAlice, payload);
            var simpleSignHex = "01" + Utils.Bytes2HexString(simpleSign).ToLower().Substring(2);
            Console.WriteLine($"simpleSignHex:\n{simpleSignHex}");

            // Extrinsic params:
            //compact length 0x3102
            //version 84
            //signer 0x00d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
            //signature 0x012a3cfc6276f33837a68145f398663f419ef90f27b77ccb67756138db2545d560da748231a05d55f9a39efde9507101ef58657314ad0bb81c7b06a49805fe9380
            //era 0xa500
            //nonce 0x24
            //tip 0x00
            //method 0x6803a9cf7cc945f0632a22a7028d8a83a2a153318bb3f4d04d1200afc31ee9a0537224000118537472696e6716554d700000000000a0724e18090000000000000000000001

            var paramsHex = "84" +
                addressAliceHex +
                simpleSignHex +
                eraHex + nonceHex + tipHex +
                methodHex;

            var lengthCompact = Utils.Bytes2HexString(new CompactInteger(paramsHex.Length / 2).Encode()).ToLower().Substring(2);

            paramsHex = "0x" + lengthCompact + paramsHex;
            Console.WriteLine($"paramsHex:\n{paramsHex.Substring(0, 30)}...");
            
            // Subscribtion and listening
            var taskCompletionSource = new TaskCompletionSource<(bool, Hash)>();

            // Message sending and extrinsicUpdate subscription
            var subscriptionId =
                await _substrateClient.InvokeAsync<string>("author_submitAndWatchExtrinsic", new object[] { paramsHex }, CancellationToken.None);

            _substrateClient.Listener.RegisterCallBackHandler(subscriptionId, (string subscriptionId, ExtrinsicStatus extrinsicUpdate) =>
            {
                if (extrinsicUpdate.ExtrinsicState == ExtrinsicState.Finalized ||
                    extrinsicUpdate.ExtrinsicState == ExtrinsicState.Dropped ||
                    extrinsicUpdate.ExtrinsicState == ExtrinsicState.Invalid)
                {
                    taskCompletionSource.SetResult((true, extrinsicUpdate.Hash));
                }


                Console.WriteLine($"extrinsicUpdate:\n{extrinsicUpdate.ExtrinsicState}");
            });

            var finished = await Task.WhenAny(taskCompletionSource.Task, Task.Delay(TimeSpan.FromMinutes(1)));
            Assert.AreEqual(taskCompletionSource.Task, finished, "Test timed out waiting for final callback");

        }
    }

}







