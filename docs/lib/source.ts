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

function getAllDocFiles(): string[] {
  try {
    const files = fs.readdirSync(DOCS_DIR)
    return files.filter(file => file.endsWith('.md') || file.endsWith('.mdx'))
  } catch (error) {
    console.error('Error reading docs directory:', error)
    return []
  }
}

function readDocFile(filename: string): DocPage | null {
  try {
    const filePath = path.join(DOCS_DIR, filename)
    const fileContents = fs.readFileSync(filePath, 'utf8')
    const { data, content } = matter(fileContents)
    const meta = data as DocMeta
    
    const slug = filename.replace(/\.(md|mdx)$/, '')
    
    return {
      slug: slug === 'index' ? [] : [slug],
      data: {
        title: meta.title || slug,
        description: meta.description,
        content,
        toc: [],
        full: false,
        body: () => null,
      },
    }
  } catch (error) {
    console.error(`Error reading doc file ${filename}:`, error)
    return null
  }
}

export const source = {
  getPage(slugParam?: string[]): DocPage | null {
    if (!slugParam || slugParam.length === 0) {
      return readDocFile('index.mdx')
    }
    
    const slug = slugParam[0]
    let page = readDocFile(`${slug}.md`)
    if (!page) {
      page = readDocFile(`${slug}.mdx`)
    }
    return page
  },

  generateParams(): { slug: string[] }[] {
    const files = getAllDocFiles()
    return files.map(file => {
      const slug = file.replace(/\.(md|mdx)$/, '')
      return { slug: slug === 'index' ? [] : [slug] }
    })
  },

  get pageTree() {
    const files = getAllDocFiles()
    const pages = files
      .map(readDocFile)
      .filter((p): p is DocPage => p !== null)
      .sort((a, b) => {
        if (a.slug.length === 0) return -1
        if (b.slug.length === 0) return 1
        return a.data.title.localeCompare(b.data.title)
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
