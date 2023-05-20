const express = require("express");
const bodyParser = require('body-parser');
const JsonDB = require('node-json-db').JsonDB;
const Config = require('node-json-db/dist/lib/JsonDBConfig').Config;
const uuid = require("uuid");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

const app = express();

const dbConfig = new Config("TOTPDatabase", true, false, '/')
const db = new JsonDB(dbConfig);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.post("/api/register", (req, res) => {
    //Generamos el id
    const id = uuid.v4();
    try {
      // Definimos la ruta en la que se almacenará el usuario
      const ruta = `/user/${id}`;
      // Creamos la cadena secreta
      const cadena_secreta_temporal = speakeasy.generateSecret();
      // Almacenamos la cadena en la bd, asociandola con el id creado anteriormente.
      db.push(ruta, { id, cadena_secreta_temporal });
      // Generamos el código QR y lo mostramos por consola
      const qr = qrcode.toString(cadena_secreta_temporal.otpauth_url, function(err, url) {
        console.log(url)
      })
      // Devolvemos el id y la cadena secreta en formato Base32
      res.json({ id, secret: cadena_secreta_temporal.base32 })
    } catch(e) {
      // Controlamos las posibles excepciones y las mostramos por consola
      console.log(e);
      res.status(500).json({ message: 'Error generando la cadena secreta'})
    }
});

app.post("/api/verify", async (req,res) => {
    const { userId, token } = req.body;
    try {
      const ruta = `/user/${userId}`;
      // Se obtiene el usuario de la bd a partir de la ruta en la que se almacenó
      const user = await db.getData(ruta);
      // Se obtiene la cadena secreta del usuario
      const { base32: secret } = user.cadena_secreta_temporal;
      // Comprueba si el token corresponde con la cadena secreta asociada al usuario
      const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
      });

      if (verified) {
        // Si corresponde, se actualiza el usuario y se devuelve true
        await db.push(ruta, { id: userId, cadena_secreta: user.cadena_secreta_temporal });
        res.json({ verified: true })
      } else {
        res.json({ verified: false})
      }
    } catch(error) {
      console.error(error);
      res.status(500).json({ message: 'Error obteniendo el usuario'})
    };
});

app.post("/api/validate", async (req, res) => {
  const { userId, token } = req.body;
  try {
      const ruta = `/user/${userId}`;
      // Obtiene el usuario de la bd y su cadena secreta, como en el método anterior
      const user = await db.getData(ruta);
      const { base32: secret } = user.cadena_secreta;

      // Devuelve true si el token corresponde con la cadena secreta asociada al usuario
      const validated = speakeasy.totp.verify({
          secret,
          encoding: 'base32',
          token,
          window: 1 // Se especifica el tiempo de validez de cada código generado, en este caso 30 segs.
      });

      // Se devuelve el resultado de la validación
      if (validated) {
          res.json({ validated: true })
      } else { 
        res.json({ validated: false })
      }
      
  } catch (e) {
      console.error(e);
      res.status(500).json({ message: 'Error obteniendo el usuario' })
  };
})

const port = 3001;
app.listen(port, () => {
  console.log(`App is running on PORT: ${port}.`);
});