import mongoose from 'mongoose'

const Schema = mongoose.Schema

const credentialSchema = new Schema({
  credId: String,
  userId: {type: Schema.Types.ObjectId, ref: 'User'},
  publicKey: [Number],
  type: String,
  transports: [String],
  counter: {type: Number, default: 0},
  aaguId: String,
  attestationType: {type: String, enum: ['direct', 'indirect', 'none']}
},{
  timestamps: true,
})

const Credential = mongoose.model('Credential', credentialSchema)

export { Credential }
