#pragma once

struct tPlayerEntity {
	char pad[0x288];
	float m_fXPos; //0x28C
	float m_fYPos; //0x290
	char pad[10];
	int m_iCoins; //0x12B0
};