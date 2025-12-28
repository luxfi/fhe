import Link from 'next/link'

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-8 bg-gradient-to-b from-background to-muted">
      <div className="max-w-4xl text-center">
        <h1 className="text-5xl font-bold mb-4">Lux TFHE</h1>
        <p className="text-xl text-muted-foreground mb-8">
          Pure Go implementation of Threshold Fully Homomorphic Encryption for the Lux Network.
          Compute on encrypted data without ever decrypting it.
        </p>
        <div className="flex gap-4 justify-center">
          <Link 
            href="/docs" 
            className="px-6 py-3 bg-primary text-primary-foreground rounded-lg font-medium hover:opacity-90 transition"
          >
            Documentation
          </Link>
          <a 
            href="https://github.com/luxfi/tfhe" 
            className="px-6 py-3 border border-border rounded-lg font-medium hover:bg-muted transition"
          >
            GitHub
          </a>
        </div>
        
        <div className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-8 text-left">
          <div className="p-6 bg-card rounded-lg border">
            <h3 className="text-lg font-semibold mb-2">Pure Go</h3>
            <p className="text-muted-foreground">
              No CGO, no external dependencies. Compiles anywhere Go runs.
            </p>
          </div>
          <div className="p-6 bg-card rounded-lg border">
            <h3 className="text-lg font-semibold mb-2">Patent-Safe</h3>
            <p className="text-muted-foreground">
              Classic boolean circuit approach. No patented LUT techniques.
            </p>
          </div>
          <div className="p-6 bg-card rounded-lg border">
            <h3 className="text-lg font-semibold mb-2">Blockchain Ready</h3>
            <p className="text-muted-foreground">
              Public key encryption, deterministic RNG, full serialization.
            </p>
          </div>
        </div>
      </div>
    </main>
  )
}
