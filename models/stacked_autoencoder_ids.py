import torch
from torch import nn

class StackedAutoencoderIDS(nn.Module):
    def __init__(self, input_shape: tuple, latent_dim: int = 128):
        """
        input_shape: (C, H, W) — number of channels, height, and width of input feature map.
        latent_dim: dimensionality of the latent (compressed) representation.
        """
        super().__init__()

        # Dynamically compute flattened input size based on input shape
        self.input_shape = input_shape
        C, H, W = input_shape
        flat_dim = C * H * W
        self._flat_dim = flat_dim

        # ---- Encoder ----
        # Uses progressive compression with non-linear activations.
        # The layers automatically scale based on flat_dim to avoid hardcoding sizes.
        encoder_layers = [
            nn.Linear(flat_dim, max(flat_dim // 2, latent_dim * 2)),
            nn.ReLU(),
            nn.Linear(max(flat_dim // 2, latent_dim * 2), max(flat_dim // 8, latent_dim)),
            nn.ReLU(),
            nn.Linear(max(flat_dim // 8, latent_dim), latent_dim)
        ]
        self.encoder = nn.Sequential(*encoder_layers)

        # ---- Decoder ----
        # Mirrors the encoder architecture to reconstruct the input.
        decoder_layers = [
            nn.Linear(latent_dim, max(flat_dim // 8, latent_dim)),
            nn.ReLU(),
            nn.Linear(max(flat_dim // 8, latent_dim), max(flat_dim // 2, latent_dim * 2)),
            nn.ReLU(),
            nn.Linear(max(flat_dim // 2, latent_dim * 2), flat_dim),
            nn.Sigmoid()  # outputs between 0–1
        ]
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x):
        """
        Forward pass through the autoencoder.
        Returns both the reconstructed input and the latent code.
        """
        batch_size = x.size(0)
        # Flatten (C,H,W) into a single feature vector
        x_flat = x.view(batch_size, -1)
        # Encode
        z = self.encoder(x_flat)
        # Decode
        x_recon = self.decoder(z)
        # Reshape to original format
        x_recon = x_recon.view(batch_size, *self.input_shape)
        return x_recon, z
