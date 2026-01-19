import React from 'react';

interface QRCodeDisplayProps {
  data: string;
  size?: number;
  description?: string;
}

const QRCodeDisplay: React.FC<QRCodeDisplayProps> = ({
  data,
  size = 200,
  description
}) => {
  const isBase64 = data.startsWith('data:image');

  return (
    <div className="qrcode-display">
      {isBase64 ? (
        <img src={data} alt="QR Code" style={{ width: size, height: size }} />
      ) : (
        <div>请提供有效的二维码数据</div>
      )}
      {description && <p className="qrcode-description">{description}</p>}
    </div>
  );
};

export default QRCodeDisplay;
