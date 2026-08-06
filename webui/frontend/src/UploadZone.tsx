import type { ChangeEvent } from 'react'

type Props = {
  onFileSelected: (file: File) => void
}

export default function UploadZone({ onFileSelected }: Props) {
  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (file) onFileSelected(file)
  }

  return (
    <div className="upload-zone">
      <label htmlFor="exe-upload">📁 Upload EXE</label>
      <input id="exe-upload" type="file" accept=".exe" onChange={handleChange} />
    </div>
  )
}
