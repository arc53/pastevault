/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack: (config, { isServer }) => {
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
      syncWebAssembly: true,
    }
    
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        crypto: false,
        stream: false,
        buffer: require.resolve('buffer'),
      }
    }
    
    config.module.rules.push({
      test: /\.wasm$/,
      type: 'webassembly/async',
    })
    
    return config
  },
}

module.exports = nextConfig