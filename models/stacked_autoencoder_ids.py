import torch
from torch import nn

class StackedAutoencoderIDS(nn.Module):
    # Dimensões de entrada: (1, 44, 116) -> flat_dim = 5104
    INPUT_FLAT_DIM = 5104 
    
    def __init__(self, latent_dim: int = 16):
        """
        latent_dim: Dimensionalidade da representação latente (compressão).
        """
        super().__init__()
        
        flat_dim = self.INPUT_FLAT_DIM
        
        # Dimensões Intermediárias: Usando 1/4 do tamanho da entrada como ponto
        # para a camada intermediária, para que a compressão seja mais agressiva.
        hidden_dim = flat_dim // 4  # 5104 // 4 = 1276

        # ---- Encoder ----
        self.encoder = nn.Sequential(
            nn.Linear(flat_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim) # Compressão para latent_dim
        )

        # ---- Decoder ----
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim), # Inversão
            nn.ReLU(),
            nn.Linear(hidden_dim, flat_dim),
            nn.Sigmoid() # Saída entre 0 e 1, útil após normalizar a entrada
        )

    def forward(self, x):
        """
        x: Espera a entrada na forma (batch_size, 1, 44, 116).
        """
        batch_size = x.size(0)
        
        # Achatamento da entrada: (B, 1, 44, 116) -> (B, 5104)
        x_flat = x.view(batch_size, -1)
        
        # Codificação e Decodificação
        z = self.encoder(x_flat)
        x_recon_flat = self.decoder(z)
        
        # Remodelagem da saída para o formato original (B, 1, 44, 116)
        # O self.INPUT_FLAT_DIM deve ser (1, 44, 116) para o reshape
        x_recon = x_recon_flat.view(batch_size, 1, 44, 116)
        
        # Retorna a reconstrução e o código latente
        return x_recon, z