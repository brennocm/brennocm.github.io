// ============================================
// Picinfo - Image Metadata Extractor
// ============================================

// ============================================
// Internationalization
// ============================================
const i18n = {
    'pt-BR': {
        title: 'Picinfo',
        subtitle: 'Extraia metadados de imagens com segurança',
        privacyBadge: 'Sua imagem nunca sai do navegador. Processamento 100% local.',
        uploadLabel: 'Arraste uma imagem ou clique para selecionar',
        uploadHint: 'Suporta JPG e PNG',
        dropText: 'Solte a imagem aqui',
        analyze: 'Analisar',
        clear: 'Limpar',
        export: 'Exportar JSON',
        basicInfo: 'Informações Básicas',
        exifData: 'Dados EXIF',
        gpsData: 'Dados de Localização',
        cameraInfo: 'Informações da Câmera',
        noData: 'Nenhum dado disponível',
        fileName: 'Nome do Arquivo',
        fileSize: 'Tamanho',
        fileType: 'Tipo',
        dimensions: 'Dimensões',
        lastModified: 'Última Modificação',
        dateTaken: 'Data da Foto',
        software: 'Software',
        colorSpace: 'Espaço de Cores',
        orientation: 'Orientação',
        latitude: 'Latitude',
        longitude: 'Longitude',
        altitude: 'Altitude',
        viewOnMap: 'Ver no Mapa',
        cameraMake: 'Fabricante',
        cameraModel: 'Modelo',
        lens: 'Lente',
        focalLength: 'Distância Focal',
        aperture: 'Abertura',
        exposureTime: 'Tempo de Exposição',
        iso: 'ISO',
        flash: 'Flash',
        flashOn: 'Disparado',
        flashOff: 'Não disparado',
        gpsWarningTitle: 'Dados de Localização Detectados',
        gpsWarningText: 'Esta imagem contém coordenadas GPS. Considere remover esses dados antes de compartilhar.',
        guideTitle: 'Guia: Metadados de Imagem',
        guideIntro: 'O que são Metadados?',
        guideIntroText: 'Metadados são informações adicionais armazenadas dentro de arquivos de imagem. Eles podem incluir dados técnicos sobre a câmera, configurações usadas, data e hora da captura, e até localização GPS.',
        guideTypes: 'Tipos de Metadados',
        guideTypesItems: [
            'EXIF: Dados técnicos da câmera e configurações de captura',
            'GPS: Coordenadas geográficas de onde a foto foi tirada',
            'IPTC: Informações editoriais como título, autor e copyright',
            'XMP: Metadados extensíveis usados por softwares de edição'
        ],
        guidePrivacy: 'Implicações de Privacidade',
        guidePrivacyItems: [
            'Fotos podem revelar sua localização exata através de coordenadas GPS',
            'Data e hora podem expor seus padrões de rotina',
            'Informações do dispositivo podem identificar seu equipamento',
            'Sempre revise e remova metadados sensíveis antes de compartilhar'
        ]
    },
    'en-US': {
        title: 'Picinfo',
        subtitle: 'Extract image metadata securely',
        privacyBadge: 'Your image never leaves your browser. 100% local processing.',
        uploadLabel: 'Drag an image or click to select',
        uploadHint: 'Supports JPG and PNG',
        dropText: 'Drop the image here',
        analyze: 'Analyze',
        clear: 'Clear',
        export: 'Export JSON',
        basicInfo: 'Basic Information',
        exifData: 'EXIF Data',
        gpsData: 'Location Data',
        cameraInfo: 'Camera Information',
        noData: 'No data available',
        fileName: 'File Name',
        fileSize: 'Size',
        fileType: 'Type',
        dimensions: 'Dimensions',
        lastModified: 'Last Modified',
        dateTaken: 'Date Taken',
        software: 'Software',
        colorSpace: 'Color Space',
        orientation: 'Orientation',
        latitude: 'Latitude',
        longitude: 'Longitude',
        altitude: 'Altitude',
        viewOnMap: 'View on Map',
        cameraMake: 'Make',
        cameraModel: 'Model',
        lens: 'Lens',
        focalLength: 'Focal Length',
        aperture: 'Aperture',
        exposureTime: 'Exposure Time',
        iso: 'ISO',
        flash: 'Flash',
        flashOn: 'Fired',
        flashOff: 'Did not fire',
        gpsWarningTitle: 'Location Data Detected',
        gpsWarningText: 'This image contains GPS coordinates. Consider removing this data before sharing.',
        guideTitle: 'Guide: Image Metadata',
        guideIntro: 'What is Metadata?',
        guideIntroText: 'Metadata is additional information stored within image files. It can include technical data about the camera, settings used, date and time of capture, and even GPS location.',
        guideTypes: 'Types of Metadata',
        guideTypesItems: [
            'EXIF: Technical camera data and capture settings',
            'GPS: Geographic coordinates of where the photo was taken',
            'IPTC: Editorial information like title, author, and copyright',
            'XMP: Extensible metadata used by editing software'
        ],
        guidePrivacy: 'Privacy Implications',
        guidePrivacyItems: [
            'Photos can reveal your exact location through GPS coordinates',
            'Date and time can expose your routine patterns',
            'Device information can identify your equipment',
            'Always review and remove sensitive metadata before sharing'
        ]
    }
};

// ============================================
// State
// ============================================
const state = {
    lang: document.documentElement.getAttribute('data-lang') || 'pt-BR',
    currentFile: null,
    metadata: null
};

// ============================================
// EXIF Parser (JPEG & PNG Support)
// ============================================

function parseExif(arrayBuffer) {
    try {
        const dataView = new DataView(arrayBuffer);
        const exifData = {};

        if (dataView.byteLength < 4) return exifData;

        // JPEG signature (0xFFD8)
        if (dataView.getUint16(0) === 0xFFD8) {
            return parseJpeg(dataView, exifData);
        }
        // PNG signature (0x89504E47)
        else if (dataView.getUint32(0) === 0x89504E47) {
            return parsePng(dataView, exifData);
        }

        return exifData; // Unsupported format
    } catch (e) {
        console.error("Error parsing Metadata:", e);
        return {};
    }
}

function parseJpeg(dataView, exifData) {
    let offset = 2;
    const length = dataView.byteLength;
    let iterationCount = 0;
    const maxIterations = 1000;

    while (offset < length && iterationCount < maxIterations) {
        iterationCount++;
        if (offset + 1 >= length) break;
        if (dataView.getUint8(offset) !== 0xFF) {
            offset++;
            continue;
        }

        const marker = dataView.getUint8(offset + 1);

        // APP1 marker (EXIF)
        if (marker === 0xE1) {
            if (offset + 10 >= length) break;
            const exifOffset = offset + 4;

            // Check for "Exif" string
            const exifStr = String.fromCharCode(
                dataView.getUint8(exifOffset),
                dataView.getUint8(exifOffset + 1),
                dataView.getUint8(exifOffset + 2),
                dataView.getUint8(exifOffset + 3)
            );

            if (exifStr === 'Exif') {
                // JPEG Exif header has 6 bytes padding ("Exif\0\0") before TIFF header
                const tiffOffset = exifOffset + 6;
                parseTiffHeader(dataView, tiffOffset, exifData);
            }
            break;
        }

        // Move to next marker
        if (marker !== 0x00 && marker !== 0xFF) {
            if (offset + 3 >= length) break;
            const segmentLength = dataView.getUint16(offset + 2);
            offset += segmentLength + 2;
        } else {
            offset++;
        }
    }
    return exifData;
}

function parsePng(dataView, exifData) {
    let offset = 8; // Skip PNG signature
    const length = dataView.byteLength;
    let iterationCount = 0;
    const maxIterations = 1000;

    while (offset < length && iterationCount < maxIterations) {
        iterationCount++;
        if (offset + 8 > length) break; // Need length + type

        const chunkLength = dataView.getUint32(offset);
        const chunkType = String.fromCharCode(
            dataView.getUint8(offset + 4),
            dataView.getUint8(offset + 5),
            dataView.getUint8(offset + 6),
            dataView.getUint8(offset + 7)
        );

        // The 'eXIf' chunk contains raw TIFF/Exif data (without JPEG's "Exif\0\0" header)
        if (chunkType === 'eXIf') {
            const tiffOffset = offset + 8;
            parseTiffHeader(dataView, tiffOffset, exifData);
            break;
        }

        // Move to next chunk: Length (4) + Type (4) + Data (chunkLength) + CRC (4)
        offset += 12 + chunkLength;
    }
    return exifData;
}

function parseTiffHeader(dataView, tiffOffset, exifData) {
    if (tiffOffset + 8 >= dataView.byteLength) return;

    const isLittleEndian = dataView.getUint16(tiffOffset) === 0x4949;
    const ifdOffset = dataView.getUint32(tiffOffset + 4, isLittleEndian);

    if (tiffOffset + ifdOffset < dataView.byteLength) {
        parseIFD(dataView, tiffOffset, tiffOffset + ifdOffset, isLittleEndian, exifData, 0);
    }
}

function parseIFD(dataView, tiffOffset, ifdOffset, isLittleEndian, exifData, depth) {
    // PROTECTION 1: Limit recursion depth to prevent Stack Overflow
    if (depth > 5) return;

    // PROTECTION 2: Validate buffer bounds
    if (ifdOffset + 2 > dataView.byteLength) return;

    try {
        const numEntries = dataView.getUint16(ifdOffset, isLittleEndian);

        // PROTECTION 3: Sanity check on number of entries
        if (numEntries > 1000) return;

        const tagNames = {
            0x010F: 'Make',
            0x0110: 'Model',
            0x0112: 'Orientation',
            0x011A: 'XResolution',
            0x011B: 'YResolution',
            0x0132: 'DateTime',
            0x8769: 'ExifIFDPointer',
            0x8825: 'GPSInfoIFDPointer',
            0x829A: 'ExposureTime',
            0x829D: 'FNumber',
            0x8827: 'ISOSpeedRatings',
            0x9003: 'DateTimeOriginal',
            0x9004: 'DateTimeDigitized',
            0x920A: 'FocalLength',
            0x9209: 'Flash',
            0xA001: 'ColorSpace',
            0xA002: 'PixelXDimension',
            0xA003: 'PixelYDimension',
            0xA405: 'FocalLengthIn35mmFilm',
            // GPS Tags
            0x0001: 'GPSLatitudeRef',
            0x0002: 'GPSLatitude',
            0x0003: 'GPSLongitudeRef',
            0x0004: 'GPSLongitude',
            0x0005: 'GPSAltitudeRef',
            0x0006: 'GPSAltitude'
        };

        for (let i = 0; i < numEntries; i++) {
            const entryOffset = ifdOffset + 2 + (i * 12);

            // PROTECTION 4: Check bounds before reading entry
            if (entryOffset + 12 > dataView.byteLength) break;

            const tag = dataView.getUint16(entryOffset, isLittleEndian);
            const type = dataView.getUint16(entryOffset + 2, isLittleEndian);
            const count = dataView.getUint32(entryOffset + 4, isLittleEndian);
            const valueOffset = entryOffset + 8;

            const tagName = tagNames[tag];
            if (!tagName) continue;

            // PROTECTION 5: Sanity check on count
            if (count > 10000) continue;

            // Parse value based on type
            let value;
            try {
                switch (type) {
                    case 1: // BYTE
                    case 7: // UNDEFINED
                        value = dataView.getUint8(valueOffset);
                        break;
                    case 2: // ASCII
                        if (count > 4) {
                            const strOffset = tiffOffset + dataView.getUint32(valueOffset, isLittleEndian);
                            // Validate string offset
                            if (strOffset + count <= dataView.byteLength) {
                                value = readString(dataView, strOffset, Math.min(count - 1, 1000));
                            }
                        } else {
                            value = readString(dataView, valueOffset, count - 1);
                        }
                        break;
                    case 3: // SHORT
                        value = dataView.getUint16(valueOffset, isLittleEndian);
                        break;
                    case 4: // LONG
                        value = dataView.getUint32(valueOffset, isLittleEndian);
                        break;
                    case 5: // RATIONAL
                        const ratOffset = tiffOffset + dataView.getUint32(valueOffset, isLittleEndian);
                        if (ratOffset + 8 <= dataView.byteLength) {
                            const numerator = dataView.getUint32(ratOffset, isLittleEndian);
                            const denominator = dataView.getUint32(ratOffset + 4, isLittleEndian);
                            value = denominator !== 0 ? numerator / denominator : 0;
                        }
                        break;
                    case 10: // SRATIONAL
                        const sratOffset = tiffOffset + dataView.getUint32(valueOffset, isLittleEndian);
                        if (sratOffset + 8 <= dataView.byteLength) {
                            const snum = dataView.getInt32(sratOffset, isLittleEndian);
                            const sden = dataView.getInt32(sratOffset + 4, isLittleEndian);
                            value = sden !== 0 ? snum / sden : 0;
                        }
                        break;
                    default:
                        continue;
                }
            } catch (e) {
                // Skip invalid entries
                continue;
            }

            if (value !== undefined) {
                exifData[tagName] = value;
            }

            // Parse sub-IFDs with depth + 1
            if (tagName === 'ExifIFDPointer' || tagName === 'GPSInfoIFDPointer') {
                const subIfdOffset = tiffOffset + value;
                // Validate pointer is within bounds
                if (subIfdOffset > 0 && subIfdOffset < dataView.byteLength) {
                    parseIFD(dataView, tiffOffset, subIfdOffset, isLittleEndian, exifData, depth + 1);
                }
            }
        }
    } catch (e) {
        console.warn("Error reading IFD (corrupted or malicious file):", e);
        return; // Fail safely
    }
}

function readString(dataView, offset, length) {
    // PROTECTION: Bounds checking
    if (offset < 0 || offset + length > dataView.byteLength) {
        return '';
    }

    let str = '';
    const maxLength = Math.min(length, 1000); // Limit string length

    for (let i = 0; i < maxLength; i++) {
        const char = dataView.getUint8(offset + i);
        if (char === 0) break;
        str += String.fromCharCode(char);
    }
    return str;
}

function parseGPSCoordinate(coord, ref) {
    if (!coord || typeof coord !== 'object') return null;

    // Simplified: just return the value as stored
    return coord;
}

function convertDMSToDecimal(degrees, minutes, seconds, ref) {
    let decimal = degrees + (minutes / 60) + (seconds / 3600);
    if (ref === 'S' || ref === 'W') {
        decimal = -decimal;
    }
    return decimal;
}

// ============================================
// Utility Functions
// ============================================

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateStr) {
    if (!dateStr) return null;
    // EXIF date format: "YYYY:MM:DD HH:MM:SS"
    const parts = dateStr.split(' ');
    if (parts.length >= 1) {
        const dateParts = parts[0].split(':');
        if (dateParts.length === 3) {
            const date = new Date(dateParts[0], dateParts[1] - 1, dateParts[2]);
            if (parts[1]) {
                const timeParts = parts[1].split(':');
                date.setHours(timeParts[0], timeParts[1], timeParts[2] || 0);
            }
            return date.toLocaleString(state.lang === 'pt-BR' ? 'pt-BR' : 'en-US');
        }
    }
    return dateStr;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    // Also escape quotes for attribute context safety
    return div.innerHTML
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Safe render function - escapes ALL values to prevent XSS
function safeRender(value, suffix = '') {
    if (value === undefined || value === null) return '';
    // Convert to string and escape
    return escapeHtml(String(value)) + suffix;
}

// Sanitize filename - remove special characters and path components
function sanitizeFilename(filename) {
    if (!filename) return 'file';
    // Remove path separators and special characters, keep only alphanumeric, dash, underscore
    return filename
        .replace(/\.[^.]+$/, '') // Remove extension
        .replace(/[^a-zA-Z0-9_-]/g, '_') // Replace special chars with underscore
        .replace(/_+/g, '_') // Collapse multiple underscores
        .replace(/^_|_$/g, '') // Remove leading/trailing underscores
        .substring(0, 50) || 'file'; // Limit length
}

// ============================================
// UI Functions
// ============================================

function handleFileSelect(file) {
    if (!file || !file.type.startsWith('image/')) {
        return;
    }

    state.currentFile = file;

    // Show preview
    const previewSection = document.getElementById('previewSection');
    const previewImage = document.getElementById('previewImage');
    const previewFilename = document.getElementById('previewFilename');
    const previewSize = document.getElementById('previewSize');
    const previewType = document.getElementById('previewType');
    const previewModified = document.getElementById('previewModified');

    const reader = new FileReader();
    reader.onload = function (e) {
        previewImage.src = e.target.result;

        // Get image dimensions
        const img = new Image();
        img.onload = function () {
            document.getElementById('previewDimensions').textContent =
                `${img.width} x ${img.height}`;
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);

    previewFilename.textContent = file.name;
    previewSize.textContent = formatFileSize(file.size);
    previewType.textContent = file.type;
    previewModified.textContent = new Date(file.lastModified).toLocaleString(
        state.lang === 'pt-BR' ? 'pt-BR' : 'en-US'
    );

    previewSection.classList.add('visible');

    // Auto-analyze
    analyzeImage();
}

function analyzeImage() {
    if (!state.currentFile) return;

    const lang = i18n[state.lang];
    const reader = new FileReader();

    reader.onload = function (e) {
        const arrayBuffer = e.target.result;
        const exifData = parseExif(arrayBuffer);

        state.metadata = {
            basic: {
                fileName: state.currentFile.name,
                fileSize: formatFileSize(state.currentFile.size),
                fileType: state.currentFile.type,
                lastModified: new Date(state.currentFile.lastModified).toLocaleString(
                    state.lang === 'pt-BR' ? 'pt-BR' : 'en-US'
                )
            },
            exif: exifData,
            hasGPS: !!(exifData.GPSLatitude || exifData.GPSLongitude)
        };

        renderResults();
    };

    reader.readAsArrayBuffer(state.currentFile);
}

function renderResults() {
    const lang = i18n[state.lang];
    const { basic, exif, hasGPS } = state.metadata;

    const resultsSection = document.getElementById('resultsSection');
    resultsSection.classList.add('visible');

    let html = '';

    // GPS Warning
    if (hasGPS) {
        html += `
            <div class="warning-banner">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                <div class="warning-banner-content">
                    <h4>${lang.gpsWarningTitle}</h4>
                    <p>${lang.gpsWarningText}</p>
                </div>
            </div>
        `;
    }

    html += '<div class="metadata-grid">';

    // Basic Info Card
    html += `
        <div class="result-card">
            <div class="result-card-header">
                <div class="result-card-icon basic-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                        <circle cx="8.5" cy="8.5" r="1.5"/>
                        <polyline points="21 15 16 10 5 21"/>
                    </svg>
                </div>
                <span class="result-card-title">${lang.basicInfo}</span>
            </div>
            <div class="result-card-content">
                <div class="metadata-list">
                    <div class="metadata-item">
                        <span class="metadata-key">${lang.fileName}</span>
                        <span class="metadata-value">${escapeHtml(basic.fileName)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-key">${lang.fileSize}</span>
                        <span class="metadata-value">${basic.fileSize}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-key">${lang.fileType}</span>
                        <span class="metadata-value">${basic.fileType}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-key">${lang.lastModified}</span>
                        <span class="metadata-value">${basic.lastModified}</span>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Camera Info Card
    const hasCameraInfo = exif.Make || exif.Model || exif.FocalLength || exif.FNumber;
    html += `
        <div class="result-card">
            <div class="result-card-header">
                <div class="result-card-icon camera-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/>
                        <circle cx="12" cy="13" r="4"/>
                    </svg>
                </div>
                <span class="result-card-title">${lang.cameraInfo}</span>
            </div>
            <div class="result-card-content">
                ${hasCameraInfo ? `
                    <div class="metadata-list">
                        ${exif.Make ? `<div class="metadata-item"><span class="metadata-key">${lang.cameraMake}</span><span class="metadata-value">${safeRender(exif.Make)}</span></div>` : ''}
                        ${exif.Model ? `<div class="metadata-item"><span class="metadata-key">${lang.cameraModel}</span><span class="metadata-value">${safeRender(exif.Model)}</span></div>` : ''}
                        ${exif.FocalLength ? `<div class="metadata-item"><span class="metadata-key">${lang.focalLength}</span><span class="metadata-value">${safeRender(typeof exif.FocalLength === 'number' ? exif.FocalLength.toFixed(1) : exif.FocalLength, 'mm')}</span></div>` : ''}
                        ${exif.FNumber ? `<div class="metadata-item"><span class="metadata-key">${lang.aperture}</span><span class="metadata-value">f/${safeRender(typeof exif.FNumber === 'number' ? exif.FNumber.toFixed(1) : exif.FNumber)}</span></div>` : ''}
                        ${exif.ExposureTime ? `<div class="metadata-item"><span class="metadata-key">${lang.exposureTime}</span><span class="metadata-value">${safeRender(typeof exif.ExposureTime === 'number' && exif.ExposureTime < 1 ? `1/${Math.round(1 / exif.ExposureTime)}` : exif.ExposureTime, 's')}</span></div>` : ''}
                        ${exif.ISOSpeedRatings ? `<div class="metadata-item"><span class="metadata-key">${lang.iso}</span><span class="metadata-value">${safeRender(exif.ISOSpeedRatings)}</span></div>` : ''}
                        ${exif.Flash !== undefined ? `<div class="metadata-item"><span class="metadata-key">${lang.flash}</span><span class="metadata-value">${(typeof exif.Flash === 'number' && exif.Flash & 1) ? lang.flashOn : lang.flashOff}</span></div>` : ''}
                    </div>
                ` : `<p class="no-data">${lang.noData}</p>`}
            </div>
        </div>
    `;

    // EXIF Data Card
    const hasExifData = exif.DateTimeOriginal || exif.DateTime || exif.ColorSpace || exif.Orientation;
    html += `
        <div class="result-card">
            <div class="result-card-header">
                <div class="result-card-icon exif-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <path d="M14 2v6h6"/>
                        <path d="M16 13H8M16 17H8M10 9H8"/>
                    </svg>
                </div>
                <span class="result-card-title">${lang.exifData}</span>
            </div>
            <div class="result-card-content">
                ${hasExifData ? `
                    <div class="metadata-list">
                        ${exif.DateTimeOriginal ? `<div class="metadata-item"><span class="metadata-key">${lang.dateTaken}</span><span class="metadata-value">${safeRender(formatDate(exif.DateTimeOriginal))}</span></div>` : ''}
                        ${exif.DateTime ? `<div class="metadata-item"><span class="metadata-key">${lang.lastModified}</span><span class="metadata-value">${safeRender(formatDate(exif.DateTime))}</span></div>` : ''}
                        ${exif.ColorSpace ? `<div class="metadata-item"><span class="metadata-key">${lang.colorSpace}</span><span class="metadata-value">${safeRender(exif.ColorSpace === 1 ? 'sRGB' : exif.ColorSpace)}</span></div>` : ''}
                        ${exif.Orientation ? `<div class="metadata-item"><span class="metadata-key">${lang.orientation}</span><span class="metadata-value">${safeRender(exif.Orientation)}</span></div>` : ''}
                        ${exif.PixelXDimension && exif.PixelYDimension ? `<div class="metadata-item"><span class="metadata-key">${lang.dimensions}</span><span class="metadata-value">${safeRender(exif.PixelXDimension)} x ${safeRender(exif.PixelYDimension)}</span></div>` : ''}
                    </div>
                ` : `<p class="no-data">${lang.noData}</p>`}
            </div>
        </div>
    `;

    // GPS Data Card
    html += `
        <div class="result-card">
            <div class="result-card-header">
                <div class="result-card-icon gps-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/>
                        <circle cx="12" cy="10" r="3"/>
                    </svg>
                </div>
                <span class="result-card-title">${lang.gpsData}</span>
            </div>
            <div class="result-card-content">
                ${hasGPS ? `
                    <div class="metadata-list">
                        ${exif.GPSLatitude ? `<div class="metadata-item"><span class="metadata-key">${lang.latitude}</span><span class="metadata-value">${safeRender(exif.GPSLatitude)} ${safeRender(exif.GPSLatitudeRef || '')}</span></div>` : ''}
                        ${exif.GPSLongitude ? `<div class="metadata-item"><span class="metadata-key">${lang.longitude}</span><span class="metadata-value">${safeRender(exif.GPSLongitude)} ${safeRender(exif.GPSLongitudeRef || '')}</span></div>` : ''}
                        ${exif.GPSAltitude ? `<div class="metadata-item"><span class="metadata-key">${lang.altitude}</span><span class="metadata-value">${safeRender(typeof exif.GPSAltitude === 'number' ? exif.GPSAltitude.toFixed(1) : exif.GPSAltitude, 'm')}</span></div>` : ''}
                    </div>
                ` : `<p class="no-data">${lang.noData}</p>`}
            </div>
        </div>
    `;

    html += '</div>';

    resultsSection.innerHTML = html;
}

function clearAll() {
    state.currentFile = null;
    state.metadata = null;

    document.getElementById('previewSection').classList.remove('visible');
    document.getElementById('resultsSection').classList.remove('visible');
    document.getElementById('resultsSection').innerHTML = '';
    document.getElementById('fileInput').value = '';
}

function exportJSON() {
    if (!state.metadata) return;

    const dataStr = JSON.stringify(state.metadata, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    // Sanitize filename to prevent path traversal and special character issues
    const safeName = sanitizeFilename(state.currentFile.name);
    a.download = `metadata_${safeName}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ============================================
// Event Listeners
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const clearBtn = document.getElementById('clearBtn');
    const exportBtn = document.getElementById('exportBtn');

    // File input change
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFileSelect(e.target.files[0]);
            }
        });
    }

    // Drop zone events
    if (dropZone) {
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                handleFileSelect(e.dataTransfer.files[0]);
            }
        });
    }

    // Clear button
    if (clearBtn) {
        clearBtn.addEventListener('click', clearAll);
    }

    // Export button
    if (exportBtn) {
        exportBtn.addEventListener('click', exportJSON);
    }
});
