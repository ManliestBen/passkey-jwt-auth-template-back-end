import mongoose from 'mongoose'

const Schema = mongoose.Schema

const credentialSchema = new Schema({
  userId: {type: Schema.Types.ObjectId, ref: 'User'},
  publicKey: String,
  type: String,
  transports: [String],
  counter: {type: Number, default: 0}
},{
  timestamps: true,
})

const Credential = mongoose.model('Credential', credentialSchema)

export { Credential }
