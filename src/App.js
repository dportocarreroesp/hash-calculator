import React, { useState } from "react";
import Header from "./components/Header/Header";
import { hash_MD4, hash_MD5, hash_sha1, hash_sha256 } from "./utils";

import "./App.css";

const App = () => {
  const hashFunctions = ["MD4", "MD5", "SHA-1", "SHA-256"];

  const [hashFunctionVal, setHashFunctionVal] = useState(hashFunctions[0]);
  const [inputText, setInputText] = useState("");
  const [inputKey, setInputKey] = useState("");
  const [outputText, setOutputText] = useState("");

  const generate_hash_msg = (event) => {
    let prepareText = inputText;
    switch (hashFunctionVal) {
      case "MD4":
        prepareText = hash_MD4(inputText, inputKey);
        break;
      case "MD5":
        hash_MD5(inputText, inputKey).then((hexString) => {
          setOutputText(hexString)
        });
        break;
      case "SHA-1":
        hash_sha1(inputText, inputKey).then((hexString) => {
          setOutputText(hexString)
        });
        break;
      case "SHA-256":
        hash_sha256(inputText, inputKey).then((hexString) => {
          setOutputText(hexString)
        });
        break;
      default:
        break;
    }
    setOutputText(prepareText);
  };

  return (
    <div className="App">
      <Header></Header>
      <section>
        <h1>Calculadora de funciones hash</h1>
        <h2>Seleccione el tipo de función Hash:</h2>
        <select onChange={(e) => setHashFunctionVal(e.target.value)}>
          {hashFunctions.map((hashFunction) => (
            <option key={hashFunction} value={hashFunction}>
              {hashFunction}
            </option>
          ))}
        </select>
        Clave(HMAC opcional):
        <input
          type="text"
          onChange={(e) => setInputKey(e.target.value)}
        ></input>
        <h2>Ingrese el texto:</h2>
        <textarea onChange={(e) => setInputText(e.target.value)}></textarea>
        <button onClick={generate_hash_msg}>GENERAR:</button>
        <h2>Resultado de la función hash:</h2>
        <textarea readOnly value={outputText}></textarea>
        <h2> </h2>
      </section>
    </div>
  );
};

export default App;
