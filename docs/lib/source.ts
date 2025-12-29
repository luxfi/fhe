import fs from 'fs'
import path from 'path'
import matter from 'gray-matter'

const DOCS_DIR = path.join(process.cwd(), 'content/docs')

export interface DocPage {
  slug: string[]
  data: {
    title: string
    description?: string
    content: string
    toc?: any
    full?: boolean
    body: any
  }
}

interface DocMeta {
  title?: string
  description?: string
  [key: string]: any
}

function getAllDocFiles(dir: string = DOCS_DIR, prefix: string[] = []): { file: string; slug: string[] }[] {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true })
    const results: { file: string; slug: string[] }[] = []
    
    for (const entry of entries) {
      if (entry.isDirectory()) {
        // Recurse into subdirectories
        const subResults = getAllDocFiles(
          path.join(dir, entry.name),
          [...prefix, entry.name]
        )
        results.push(...subResults)
      } else if (entry.name.endsWith('.md') || entry.name.endsWith('.mdx')) {
        const slug = entry.name.replace(/\.(md|mdx)$/, '')
        const fullSlug = slug === 'index' ? prefix : [...prefix, slug]
        results.push({
          file: path.join(dir, entry.name),
          slug: fullSlug,
        })
      }
    }
    
    return results
  } catch (error) {
    console.error('Error reading docs directory:', error)
    return []
  }
}

function readDocFile(filePath: string, slug: string[]): DocPage | null {
  try {
    const fileContents = fs.readFileSync(filePath, 'utf8')
    const { data, content } = matter(fileContents)
    const meta = data as DocMeta
    
    return {
      slug,
      data: {
        title: meta.title || slug[slug.length - 1] || 'Home',
        description: meta.description,
        content,
        toc: [],
        full: false,
        body: () => null,
      },
    }
  } catch (error) {
    console.error(`Error reading doc file ${filePath}:`, error)
    return null
  }
}

export const source = {
  getPage(slugParam?: string[]): DocPage | null {
    if (!slugParam || slugParam.length === 0) {
      const indexPath = path.join(DOCS_DIR, 'index.mdx')
      if (fs.existsSync(indexPath)) {
        return readDocFile(indexPath, [])
      }
      return null
    }
    
    // Build the file path from slug
    const slugPath = slugParam.join('/')
    
    // Try different file extensions and index files
    const candidates = [
      path.join(DOCS_DIR, `${slugPath}.mdx`),
      path.join(DOCS_DIR, `${slugPath}.md`),
      path.join(DOCS_DIR, slugPath, 'index.mdx'),
      path.join(DOCS_DIR, slugPath, 'index.md'),
    ]
    
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        return readDocFile(candidate, slugParam)
      }
    }
    
    return null
  },

  generateParams(): { slug: string[] }[] {
    const files = getAllDocFiles()
    return files.map(({ slug }) => ({ slug }))
  },

  get pageTree() {
    const files = getAllDocFiles()
    const pages = files
      .map(({ file, slug }) => readDocFile(file, slug))
      .filter((p): p is DocPage => p !== null)
      .sort((a, b) => {
        if (a.slug.length === 0) return -1
        if (b.slug.length === 0) return 1
        // Sort by path depth first, then alphabetically
        if (a.slug.length !== b.slug.length) {
          return a.slug.length - b.slug.length
        }
        return a.slug.join('/').localeCompare(b.slug.join('/'))
      })

    return {
      name: '',
      children: pages.map(p => ({
        type: 'page' as const,
        name: p.data.title,
        url: `/docs${p.slug.length > 0 ? '/' + p.slug.join('/') : ''}`,
      })),
    }
  },
}
